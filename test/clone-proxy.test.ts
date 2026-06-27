// Phase 1 proxies: the EIP-1167 minimal proxy (OZ Clones 5.1) + immutable args. Differential tests
// vs solc 0.8.35: a JETH factory+impl and a hand-written solc EIP-1167 (OZ-Clones-equivalent assembly)
// factory+impl are deployed on the @ethereumjs harness, and:
//   (1) the deployed clone's RUNTIME code is byte-identical to the EIP-1167 stub (plain AND with args);
//   (2) the clone delegatecalls the impl (initialize + a state read round-trip match);
//   (3) cloneDeterministic deploys to the address predictClone predicted, == solc's CREATE2;
//   (4) cloneArgs reads back the exact appended args (single uint, multiple, bytes via .decode);
//   (5) two clones of one impl have independent storage;
//   (6) isContract true for a deployed contract / false for an EOA/empty account;
//   (7) the @view/@pure-deploy reject gate (and the arg type gates).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { Address, hexToBytes, bytesToHex } from '@ethereumjs/util';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);
const strip = (h: string) => (h.startsWith('0x') ? h.slice(2) : h);

function jethAccepts(src: string): boolean {
  try {
    compile(src, { fileName: 'C.jeth' });
    return true;
  } catch {
    return false;
  }
}
function jethRejects(src: string): boolean {
  return !jethAccepts(src);
}

/** Read a deployed account's runtime code (0x-prefixed hex). */
async function codeOf(h: Harness, a: Address): Promise<string> {
  return bytesToHex(await h.evm.stateManager.getCode(a));
}

/** The canonical EIP-1167 runtime stub for an impl address (45 bytes). */
function eip1167Runtime(impl: Address): string {
  const a = strip(impl.toString()).padStart(40, '0');
  return '0x363d3d373d3d3d363d73' + a + '5af43d82803e903d91602b57fd5bf3';
}

// ---- The impl, a JETH and a solc version with identical storage/behaviour. ----
// initialize(x) sets slot0 = x (once-guard via a stored flag at slot1), who() reads slot0.
// Plus storeArgs reads its appended immutable args (cloneArgs) so a clone reads its tail.
const IMPL_JETH = `@contract class Impl {
  @state value: u256 = 0n;
  @state inited: bool = false;
  @external initialize(x: u256): void {
    require(!this.inited, "already");
    this.inited = true;
    this.value = x;
  }
  @external @view who(): u256 { return this.value; }
  @external @view oneArg(): u256 { return cloneArgs().decode(u256); }
  @external @view rawArgs(): bytes { return cloneArgs(); }
}`;
const IMPL_SOL = `contract Impl {
  uint256 public value;
  bool public inited;
  function initialize(uint256 x) external {
    require(!inited, "already");
    inited = true;
    value = x;
  }
  function who() external view returns (uint256) { return value; }
  // OZ Clones.fetchCloneArgs(address(this)) = own code[0x2d:]
  function _cloneArgs() internal view returns (bytes memory result) {
    assembly {
      let argsLen := sub(extcodesize(address()), 0x2d)
      result := mload(0x40)
      mstore(0x40, add(result, and(add(argsLen, 0x3f), not(0x1f))))
      mstore(result, argsLen)
      extcodecopy(address(), add(result, 0x20), 0x2d, argsLen)
    }
  }
  function oneArg() external view returns (uint256) {
    return abi.decode(_cloneArgs(), (uint256));
  }
  function rawArgs() external view returns (bytes memory) { return _cloneArgs(); }
}`;

// ---- A solc EIP-1167 factory (OZ Clones 5.1-equivalent assembly). ----
const FACTORY_SOL = `contract Factory {
  function clone_(address impl) external returns (address inst) {
    assembly {
      let ptr := mload(0x40)
      mstore(ptr, or(0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000, shr(64, impl)))
      mstore(add(ptr, 0x20), or(shl(192, impl), 0x5af43d82803e903d91602b57fd5bf3000000000000000000))
      inst := create(0, ptr, 0x37)
      if iszero(inst) { revert(0, 0) }
    }
  }
  function cloneDet(address impl, bytes32 salt) external returns (address inst) {
    assembly {
      let ptr := mload(0x40)
      mstore(ptr, or(0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000, shr(64, impl)))
      mstore(add(ptr, 0x20), or(shl(192, impl), 0x5af43d82803e903d91602b57fd5bf3000000000000000000))
      inst := create2(0, ptr, 0x37, salt)
      if iszero(inst) { revert(0, 0) }
    }
  }
  function predict(address impl, bytes32 salt) external view returns (address predicted) {
    assembly {
      let ptr := mload(0x40)
      mstore(ptr, or(0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000, shr(64, impl)))
      mstore(add(ptr, 0x20), or(shl(192, impl), 0x5af43d82803e903d91602b57fd5bf3000000000000000000))
      let codeHash := keccak256(ptr, 0x37)
      let p := add(ptr, 0x40)
      mstore(add(p, 0x40), codeHash)
      mstore(add(p, 0x20), salt)
      mstore(p, address())
      mstore8(add(p, 0x0b), 0xff)
      predicted := and(keccak256(add(p, 0x0b), 0x55), 0xffffffffffffffffffffffffffffffffffffffff)
    }
  }
  function cloneArgs_(address impl, bytes calldata args) external returns (address inst) {
    assembly {
      let argLen := args.length
      let ptr := mload(0x40)
      let rtLen := add(0x2d, argLen)
      mstore(ptr, or(or(0x6100003d81600a3d39f3363d3d373d3d3d363d73000000000000000000000000, shr(64, impl)), shl(232, rtLen)))
      mstore(add(ptr, 0x20), or(shl(192, impl), 0x5af43d82803e903d91602b57fd5bf3000000000000000000))
      calldatacopy(add(ptr, 0x37), args.offset, argLen)
      inst := create(0, ptr, add(0x37, argLen))
      if iszero(inst) { revert(0, 0) }
    }
  }
  function predictArgs(address impl, bytes32 salt, bytes calldata args) external view returns (address predicted) {
    assembly {
      let argLen := args.length
      let ptr := mload(0x40)
      let rtLen := add(0x2d, argLen)
      mstore(ptr, or(or(0x6100003d81600a3d39f3363d3d373d3d3d363d73000000000000000000000000, shr(64, impl)), shl(232, rtLen)))
      mstore(add(ptr, 0x20), or(shl(192, impl), 0x5af43d82803e903d91602b57fd5bf3000000000000000000))
      calldatacopy(add(ptr, 0x37), args.offset, argLen)
      let codeHash := keccak256(ptr, add(0x37, argLen))
      let p := add(add(ptr, 0x40), and(add(argLen, 0x1f), not(0x1f)))
      mstore(add(p, 0x40), codeHash)
      mstore(add(p, 0x20), salt)
      mstore(p, address())
      mstore8(add(p, 0x0b), 0xff)
      predicted := and(keccak256(add(p, 0x0b), 0x55), 0xffffffffffffffffffffffffffffffffffffffff)
    }
  }
  function cloneDetArgs(address impl, bytes32 salt, bytes calldata args) external returns (address inst) {
    assembly {
      let argLen := args.length
      let ptr := mload(0x40)
      let rtLen := add(0x2d, argLen)
      mstore(ptr, or(or(0x6100003d81600a3d39f3363d3d373d3d3d363d73000000000000000000000000, shr(64, impl)), shl(232, rtLen)))
      mstore(add(ptr, 0x20), or(shl(192, impl), 0x5af43d82803e903d91602b57fd5bf3000000000000000000))
      calldatacopy(add(ptr, 0x37), args.offset, argLen)
      inst := create2(0, ptr, add(0x37, argLen), salt)
      if iszero(inst) { revert(0, 0) }
    }
  }
}`;

const FACTORY_JETH = `@contract class Factory {
  @external clone_(impl: address): address { return clone(impl); }
  @external cloneDet(impl: address, salt: bytes32): address { return cloneDeterministic(impl, salt); }
  @external @view predict(impl: address, salt: bytes32): address { return predictClone(impl, salt); }
  @external cloneArgs_(impl: address, args: bytes): address { return cloneWithArgs(impl, args); }
  @external @view predictArgs(impl: address, salt: bytes32, args: bytes): address { return predictCloneWithArgs(impl, salt, args); }
  @external cloneDetArgs(impl: address, salt: bytes32, args: bytes): address { return cloneDeterministicWithArgs(impl, salt, args); }
  @external @view checkContract(a: address): bool { return isContract(a); }
}`;

/** Deploy the JETH factory+impl on one harness and the solc factory+impl on another; return the bits. */
async function setup() {
  const fjb = compile(FACTORY_JETH, { fileName: 'Factory.jeth' });
  const ijb = compile(IMPL_JETH, { fileName: 'Impl.jeth' });
  const fsb = compileSolidity(SPDX + FACTORY_SOL, 'Factory');
  const isb = compileSolidity(SPDX + IMPL_SOL, 'Impl');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const fj = await hj.deploy(fjb.creationBytecode);
  const fs = await hs.deploy(fsb.creation);
  const ij = await hj.deploy(ijb.creationBytecode);
  const is = await hs.deploy(isb.creation);
  return { hj, hs, fj, fs, ij, is };
}

/** Decode an address from a 32-byte returndata word. */
function addrFromWord(returnHex: string): Address {
  const h = strip(returnHex);
  return new Address(hexToBytes(('0x' + h.slice(24, 64)) as `0x${string}`));
}

describe('clone-proxy: plain EIP-1167', () => {
  it('(1) deployed clone RUNTIME is byte-identical to the EIP-1167 stub (and matches solc)', async () => {
    const { hj, hs, fj, fs, ij, is } = await setup();
    const rj = await hj.call(fj, '0x' + sel('clone_(address)') + W(BigInt(ij.toString())));
    const rs = await hs.call(fs, '0x' + sel('clone_(address)') + W(BigInt(is.toString())));
    expect(rj.success).toBe(true);
    expect(rs.success).toBe(true);
    const cj = addrFromWord(rj.returnHex);
    const cs = addrFromWord(rs.returnHex);
    const codeJ = await codeOf(hj, cj);
    const codeS = await codeOf(hs, cs);
    // each clone's runtime is the EIP-1167 stub over its own impl address
    expect(codeJ.toLowerCase()).toBe(eip1167Runtime(ij).toLowerCase());
    expect(codeS.toLowerCase()).toBe(eip1167Runtime(is).toLowerCase());
    expect(codeJ.length / 2 - 1).toBe(45); // 0x prefix removed
  });

  it('(2) the clone delegatecalls the impl: initialize + who() round-trip', async () => {
    const { hj, hs, fj, fs, ij, is } = await setup();
    const cj = addrFromWord((await hj.call(fj, '0x' + sel('clone_(address)') + W(BigInt(ij.toString())))).returnHex);
    const cs = addrFromWord((await hs.call(fs, '0x' + sel('clone_(address)') + W(BigInt(is.toString())))).returnHex);
    // initialize(99) on each clone, then who()
    await hj.call(cj, '0x' + sel('initialize(uint256)') + W(99n));
    await hs.call(cs, '0x' + sel('initialize(uint256)') + W(99n));
    const wj = await hj.call(cj, '0x' + sel('who()'));
    const ws = await hs.call(cs, '0x' + sel('who()'));
    expect(wj.returnHex).toBe(ws.returnHex);
    expect(BigInt(wj.returnHex)).toBe(99n);
    // the impl's OWN storage is untouched (delegatecall ran in the clone's context)
    expect(BigInt(await readSlot(hj, ij, 0n))).toBe(0n);
  });

  it('(5) two clones of one impl have independent storage', async () => {
    const { hj, fj, ij } = await setup();
    const c1 = addrFromWord((await hj.call(fj, '0x' + sel('clone_(address)') + W(BigInt(ij.toString())))).returnHex);
    const c2 = addrFromWord((await hj.call(fj, '0x' + sel('clone_(address)') + W(BigInt(ij.toString())))).returnHex);
    expect(c1.toString()).not.toBe(c2.toString());
    await hj.call(c1, '0x' + sel('initialize(uint256)') + W(11n));
    await hj.call(c2, '0x' + sel('initialize(uint256)') + W(22n));
    expect(BigInt((await hj.call(c1, '0x' + sel('who()'))).returnHex)).toBe(11n);
    expect(BigInt((await hj.call(c2, '0x' + sel('who()'))).returnHex)).toBe(22n);
  });
});

describe('clone-proxy: deterministic + predict', () => {
  it('(3) cloneDeterministic deploys to predictClone, == solc CREATE2', async () => {
    const { hj, hs, fj, fs, ij, is } = await setup();
    const salt = '00'.repeat(31) + '07';
    // JETH: predict then deploy
    const predJ = addrFromWord(
      (await hj.call(fj, '0x' + sel('predict(address,bytes32)') + W(BigInt(ij.toString())) + salt)).returnHex,
    );
    const deployJ = addrFromWord(
      (await hj.call(fj, '0x' + sel('cloneDet(address,bytes32)') + W(BigInt(ij.toString())) + salt)).returnHex,
    );
    expect(deployJ.toString().toLowerCase()).toBe(predJ.toString().toLowerCase());
    // solc: same salt, same impl-relative creation code -> same CREATE2 prediction formula
    const predS = addrFromWord(
      (await hs.call(fs, '0x' + sel('predict(address,bytes32)') + W(BigInt(is.toString())) + salt)).returnHex,
    );
    const deployS = addrFromWord(
      (await hs.call(fs, '0x' + sel('cloneDet(address,bytes32)') + W(BigInt(is.toString())) + salt)).returnHex,
    );
    expect(deployS.toString().toLowerCase()).toBe(predS.toString().toLowerCase());
    // the deployed clone runtime is the EIP-1167 stub
    expect((await codeOf(hj, deployJ)).toLowerCase()).toBe(eip1167Runtime(ij).toLowerCase());
    // the JETH-deployed clone is at the JETH-predicted address (proven above); that JETH prediction
    // equals what solc's CREATE2 formula computes for the SAME (factory, impl, salt) is proven in (3b).
  });

  it('(3b) JETH predict == solc predict when factory address is held equal (same-harness cross-impl)', async () => {
    // Deploy the JETH factory and the solc factory at the SAME address by deploying each first in a fresh
    // harness from the same deployer/nonce, so address() inside predict matches. Then a JETH predict and a
    // solc predict over the same impl+salt must agree (the creation code is byte-identical by construction).
    const fjb = compile(FACTORY_JETH, { fileName: 'Factory.jeth' });
    const fsb = compileSolidity(SPDX + FACTORY_SOL, 'Factory');
    const hj = await Harness.create();
    const hs = await Harness.create();
    const fj = await hj.deploy(fjb.creationBytecode);
    const fs = await hs.deploy(fsb.creation);
    expect(fj.toString()).toBe(fs.toString()); // same deployer + nonce 0 -> identical CREATE address
    const implAddr = 'cc'.repeat(20);
    const salt = '00'.repeat(30) + '1234';
    const pj = addrFromWord(
      (await hj.call(fj, '0x' + sel('predict(address,bytes32)') + W(BigInt('0x' + implAddr)) + salt)).returnHex,
    );
    const ps = addrFromWord(
      (await hs.call(fs, '0x' + sel('predict(address,bytes32)') + W(BigInt('0x' + implAddr)) + salt)).returnHex,
    );
    expect(pj.toString().toLowerCase()).toBe(ps.toString().toLowerCase());
  });
});

describe('clone-proxy: immutable args', () => {
  it('(1b) imm-args clone RUNTIME is the EIP-1167 stub (args are appended, not in code[:0x2d])', async () => {
    const { hj, hs, fj, fs, ij, is } = await setup();
    const argWord = W(0xdeadbeefn);
    const argsCd = W(BigInt(ij.toString())) + W(64n) + W(32n) + argWord; // impl, offset, len, data
    const cj = addrFromWord((await hj.call(fj, '0x' + sel('cloneArgs_(address,bytes)') + argsCd)).returnHex);
    const argsCdS = W(BigInt(is.toString())) + W(64n) + W(32n) + argWord;
    const cs = addrFromWord((await hs.call(fs, '0x' + sel('cloneArgs_(address,bytes)') + argsCdS)).returnHex);
    const codeJ = await codeOf(hj, cj);
    const codeS = await codeOf(hs, cs);
    // runtime = the EIP-1167 stub (45 bytes) ++ the 32-byte arg
    expect(codeJ.toLowerCase()).toBe((eip1167Runtime(ij) + strip(argWord)).toLowerCase());
    expect(codeS.toLowerCase()).toBe((eip1167Runtime(is) + strip(argWord)).toLowerCase());
    expect(codeJ.length / 2 - 1).toBe(45 + 32);
  });

  it('(4) cloneArgs reads back the exact appended args: single uint via .decode', async () => {
    const { hj, hs, fj, fs, ij, is } = await setup();
    const argWord = W(0x1234567890abcdefn);
    const cj = addrFromWord(
      (
        await hj.call(
          fj,
          '0x' + sel('cloneArgs_(address,bytes)') + W(BigInt(ij.toString())) + W(64n) + W(32n) + argWord,
        )
      ).returnHex,
    );
    const cs = addrFromWord(
      (
        await hs.call(
          fs,
          '0x' + sel('cloneArgs_(address,bytes)') + W(BigInt(is.toString())) + W(64n) + W(32n) + argWord,
        )
      ).returnHex,
    );
    const oj = await hj.call(cj, '0x' + sel('oneArg()'));
    const os = await hs.call(cs, '0x' + sel('oneArg()'));
    expect(oj.returnHex).toBe(os.returnHex);
    expect(BigInt(oj.returnHex)).toBe(0x1234567890abcdefn);
  });

  it('(4b) cloneArgs raw bytes round-trips multiple words (impl reads its tail verbatim)', async () => {
    const { hj, hs, fj, fs, ij, is } = await setup();
    // two 32-byte words appended
    const a1 = W(0xaaaan);
    const a2 = W(0xbbbbn);
    const data = a1 + a2; // 64 bytes
    const cdJ = W(BigInt(ij.toString())) + W(64n) + W(64n) + data;
    const cdS = W(BigInt(is.toString())) + W(64n) + W(64n) + data;
    const cj = addrFromWord((await hj.call(fj, '0x' + sel('cloneArgs_(address,bytes)') + cdJ)).returnHex);
    const cs = addrFromWord((await hs.call(fs, '0x' + sel('cloneArgs_(address,bytes)') + cdS)).returnHex);
    const rj = await hj.call(cj, '0x' + sel('rawArgs()'));
    const rs = await hs.call(cs, '0x' + sel('rawArgs()'));
    expect(rj.returnHex).toBe(rs.returnHex);
    // ABI bytes return: offset(32) + len(64) + the 64 data bytes
    expect(strip(rj.returnHex)).toBe(W(32n) + W(64n) + data);
  });

  it('(3c) cloneDeterministicWithArgs deploys to predictCloneWithArgs', async () => {
    const { hj, fj, ij } = await setup();
    const argWord = W(0xfeedn);
    const salt = '00'.repeat(31) + '09';
    const predArgsCd = W(BigInt(ij.toString())) + salt + W(96n) + W(32n) + argWord; // impl, salt, offset(96), len, data
    const pred = addrFromWord(
      (await hj.call(fj, '0x' + sel('predictArgs(address,bytes32,bytes)') + predArgsCd)).returnHex,
    );
    const detArgsCd = W(BigInt(ij.toString())) + salt + W(96n) + W(32n) + argWord;
    const r = await hj.call(fj, '0x' + sel('cloneDetArgs(address,bytes32,bytes)') + detArgsCd);
    const dep = addrFromWord(r.returnHex);
    expect(r.success).toBe(true);
    expect(dep.toString().toLowerCase()).toBe(pred.toString().toLowerCase());
    // its runtime is the stub ++ args
    expect((await codeOf(hj, dep)).toLowerCase()).toBe((eip1167Runtime(ij) + strip(argWord)).toLowerCase());
  });

  it('(3d) predictCloneWithArgs matches solc when factory addresses are equal', async () => {
    const fjb = compile(FACTORY_JETH, { fileName: 'Factory.jeth' });
    const fsb = compileSolidity(SPDX + FACTORY_SOL, 'Factory');
    const hj = await Harness.create();
    const hs = await Harness.create();
    const fj = await hj.deploy(fjb.creationBytecode);
    const fs = await hs.deploy(fsb.creation);
    expect(fj.toString()).toBe(fs.toString());
    const implAddr = 'ab'.repeat(20);
    const salt = '00'.repeat(28) + 'cafebabe';
    const argWord = W(0x42n);
    const cd = W(BigInt('0x' + implAddr)) + salt + W(96n) + W(32n) + argWord;
    const pj = addrFromWord((await hj.call(fj, '0x' + sel('predictArgs(address,bytes32,bytes)') + cd)).returnHex);
    const ps = addrFromWord((await hs.call(fs, '0x' + sel('predictArgs(address,bytes32,bytes)') + cd)).returnHex);
    expect(pj.toString().toLowerCase()).toBe(ps.toString().toLowerCase());
  });
});

describe('clone-proxy: isContract', () => {
  it('(6) true for a deployed contract, false for an EOA / empty account', async () => {
    const { hj, fj, ij } = await setup();
    const t = await hj.call(fj, '0x' + sel('checkContract(address)') + W(BigInt(ij.toString())));
    expect(BigInt(t.returnHex)).toBe(1n); // a deployed contract
    const empty = '00'.repeat(19) + 'ee';
    const f = await hj.call(fj, '0x' + sel('checkContract(address)') + W(BigInt('0x' + empty)));
    expect(BigInt(f.returnHex)).toBe(0n); // a never-deployed / empty account
    // an EOA (the default caller 0x11..11, no code)
    const eoa = await hj.call(fj, '0x' + sel('checkContract(address)') + W(BigInt('0x' + '11'.repeat(20))));
    expect(BigInt(eoa.returnHex)).toBe(0n);
  });
});

describe('clone-proxy: gates', () => {
  it('(7) a @view / @pure function that DEPLOYS is rejected', () => {
    expect(
      jethRejects(`@contract class C {
        @external @view bad(impl: address): address { return clone(impl); }
      }`),
    ).toBe(true);
    expect(
      jethRejects(`@contract class C {
        @external @pure bad(impl: address): address { return clone(impl); }
      }`),
    ).toBe(true);
    expect(
      jethRejects(`@contract class C {
        @external @view bad(impl: address, salt: bytes32): address { return cloneDeterministic(impl, salt); }
      }`),
    ).toBe(true);
    expect(
      jethRejects(`@contract class C {
        @external @view bad(impl: address, args: bytes): address { return cloneWithArgs(impl, args); }
      }`),
    ).toBe(true);
  });

  it('a nonpayable (bare @external) deploy is ACCEPTED; @external @payable too', () => {
    expect(jethAccepts(`@contract class C { @external ok(i: address): address { return clone(i); } }`)).toBe(true);
    expect(jethAccepts(`@contract class C { @external @payable ok(i: address): address { return clone(i); } }`)).toBe(
      true,
    );
  });

  it('predictClone / isContract / cloneArgs are allowed in @view (pure code/env reads)', () => {
    expect(
      jethAccepts(`@contract class C {
        @external @view p(i: address, s: bytes32): address { return predictClone(i, s); }
        @external @view c(a: address): bool { return isContract(a); }
        @external @view g(): bytes { return cloneArgs(); }
      }`),
    ).toBe(true);
  });

  it('predictClone / isContract / cloneArgs are REJECTED in @pure (they read env/code)', () => {
    expect(
      jethRejects(
        `@contract class C { @external @pure p(i: address, s: bytes32): address { return predictClone(i, s); } }`,
      ),
    ).toBe(true);
    expect(jethRejects(`@contract class C { @external @pure c(a: address): bool { return isContract(a); } }`)).toBe(
      true,
    );
    expect(jethRejects(`@contract class C { @external @pure g(): bytes { return cloneArgs(); } }`)).toBe(true);
  });

  it('arg type gates: non-address impl, non-bytes32 salt, non-bytes args', () => {
    // non-address impl
    expect(jethRejects(`@contract class C { @external f(x: u256): address { return clone(x); } }`)).toBe(true);
    // non-bytes32 salt
    expect(
      jethRejects(
        `@contract class C { @external f(i: address, s: u256): address { return cloneDeterministic(i, s); } }`,
      ),
    ).toBe(true);
    // non-bytes args
    expect(
      jethRejects(`@contract class C { @external f(i: address, a: u256): address { return cloneWithArgs(i, a); } }`),
    ).toBe(true);
    // wrong arity
    expect(
      jethRejects(`@contract class C { @external f(i: address): address { return cloneDeterministic(i); } }`),
    ).toBe(true);
    expect(jethRejects(`@contract class C { @external @view f(): bytes { return cloneArgs(1n); } }`)).toBe(true);
  });

  it('a u160 / bytes20 impl coerces to address (accepted)', () => {
    expect(jethAccepts(`@contract class C { @external f(i: u160): address { return clone(i); } }`)).toBe(true);
    expect(jethAccepts(`@contract class C { @external f(i: bytes20): address { return clone(i); } }`)).toBe(true);
  });
});
