// Diamond foundation: `@storage('ns')` namespaced storage (EIP-7201), byte-identical to a hand-written
// solc ERC-7201 namespaced-storage contract in 0.8.35. A `@storage('ns')` field lives in a logical struct
// rooted at base(ns) = keccak256(abi.encode(uint256(keccak256(bytes(ns))) - 1)) & ~0xff, laid out
// internally (sequential + packing) by the same planner as @state, then offset by that 256-bit base. This
// exercises the bigint base-slot widen: the keccak base overflows JS's 2^53, so a truncated slot fold would
// land mapping/array/scalar writes in the wrong slot. We deploy a JETH @contract and a solc mirror that uses
// the identical ERC-7201 formula + `assembly { s.slot := LOC }`, run identical calls, and diff RAW STORAGE
// SLOTS (the load-bearing check) across: a scalar at the base; two packed fields (address + uint96) sharing
// base+1; a mapping element at keccak(key . (base+slot)); a dynamic uint256[] (length at base+1, data at
// keccak(base+1)); two DISJOINT namespaces; and a @state field staying at sequential slot 0.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';
import { Address, hexToBytes, bytesToHex } from '@ethereumjs/util';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => pad32(n);
const BI = (h: string) => (!h || h === '0x' ? 0n : BigInt(h));
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const MASK = (1n << 256n) - 1n;
const hx = (s: string) => hexToBytes(('0x' + s) as `0x${string}`);

// the ERC-7201 base for a namespace string (compile-time keccak), mirrored for slot derivation.
const baseNs = (ns: string) => {
  const inner = BI('0x' + toHex(keccak(ns)));
  const word = (inner - 1n) & MASK;
  return (BI('0x' + toHex(keccak(hx(word.toString(16).padStart(64, '0'))))) & (MASK ^ 0xffn));
};
const slotEl = (key: bigint, slot: bigint) => BI('0x' + toHex(keccak(hx(pad32(key) + pad32(slot)))));
const arrData = (slot: bigint) => BI('0x' + toHex(keccak(hx(pad32(slot)))));

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};

const JETH = `class C {
  @storage('app.a') count: u256; @storage('app.a') owner: address; @storage('app.a') small: u96;
  @storage('app.m') m: mapping<u256, u256>; @storage('app.m') xs: u256[];
  @storage('app.b') flag: bool; plain: u256;
  set(c: u256, o: address, s: u96): External<void> { this.count = c; this.owner = o; this.small = s; }
  setFlag(f: bool): External<void> { this.flag = f; }
  setM(k: u256, v: u256): External<void> { this.m[k] = v; }
  pushX(v: u256): External<void> { this.xs.push(v); }
  setPlain(p: u256): External<void> { this.plain = p; } }`;

const SOL = `contract M {
  struct A { uint256 count; address owner; uint96 small; } struct Mm { mapping(uint256=>uint256) m; uint256[] xs; } struct B { bool flag; }
  function _a() internal pure returns(A storage s){ bytes32 l=keccak256(abi.encode(uint256(keccak256("app.a"))-1)) & ~bytes32(uint256(0xff)); assembly{ s.slot:=l } }
  function _m() internal pure returns(Mm storage s){ bytes32 l=keccak256(abi.encode(uint256(keccak256("app.m"))-1)) & ~bytes32(uint256(0xff)); assembly{ s.slot:=l } }
  function _b() internal pure returns(B storage s){ bytes32 l=keccak256(abi.encode(uint256(keccak256("app.b"))-1)) & ~bytes32(uint256(0xff)); assembly{ s.slot:=l } }
  uint256 plain;
  function set(uint256 c, address o, uint96 sm) external { A storage a=_a(); a.count=c; a.owner=o; a.small=sm; }
  function setFlag(bool f) external { _b().flag=f; } function setM(uint256 k, uint256 v) external { _m().m[k]=v; }
  function pushX(uint256 v) external { _m().xs.push(v); } function setPlain(uint256 p) external { plain=p; } }`;

async function dump(kind: 'J' | 'S') {
  const h = await Harness.create();
  await h.fund(me, 10n ** 20n);
  const code = kind === 'J' ? compile(JETH, { fileName: 'C.jeth' }).creationBytecode : compileSolidity(SPDX + SOL, 'M').creation;
  const a = await h.deploy(code, { caller: me });
  const owner = BI('0x' + 'Aa'.repeat(20));
  await h.call(a, sel('set(uint256,address,uint96)') + W(0x1111n) + W(owner) + W(0x222222n), { caller: me });
  await h.call(a, sel('setFlag(bool)') + W(1n), { caller: me });
  await h.call(a, sel('setM(uint256,uint256)') + W(7n) + W(0x9999n), { caller: me });
  await h.call(a, sel('pushX(uint256)') + W(0x55n), { caller: me });
  await h.call(a, sel('pushX(uint256)') + W(0x66n), { caller: me });
  await h.call(a, sel('setPlain(uint256)') + W(0x7777n), { caller: me });
  const rd = async (slot: bigint) => BI(bytesToHex(await h.evm.stateManager.getStorage(a, hx(pad32(slot)))));
  const bA = baseNs('app.a'), bM = baseNs('app.m'), bB = baseNs('app.b');
  return {
    count: await rd(bA), packed: await rd(bA + 1n), m7: await rd(slotEl(7n, bM)), xslen: await rd(bM + 1n),
    xs0: await rd(arrData(bM + 1n)), xs1: await rd(arrData(bM + 1n) + 1n), flag: await rd(bB), plain: await rd(0n),
  };
}

describe('@storage(ns) namespaced storage (EIP-7201)', () => {
  it('raw storage slots byte-identical to a solc ERC-7201 mirror', async () => {
    const [j, s] = [await dump('J'), await dump('S')];
    expect(j).toEqual(s);
    // non-vacuity: the values landed, and at the keccak base (NOT sequential slot 0).
    expect(j.count).toBe(0x1111n);
    expect(j.packed).toBe(BI('0x' + 'Aa'.repeat(20)) | (0x222222n << 160n));
    expect(j.m7).toBe(0x9999n);
    expect(j.xslen).toBe(2n);
    expect(j.xs0).toBe(0x55n);
    expect(j.xs1).toBe(0x66n);
    expect(j.flag).toBe(1n);
    expect(j.plain).toBe(0x7777n); // @state stays disjoint at slot 0
  });

  it('gate: @storage combined with a banned slot-model decorator (@state/@constant/@immutable) -> JETH481', () => {
    // The other slot models are now spelled natively (@state = a bare field, @constant/@immutable = `static`),
    // so the only way to still WRITE @state/@constant/@immutable alongside a (kept) @storage field is a banned
    // decorator, caught by the stage-2 ban pre-pass (JETH481). @storage itself stays a supported decorator.
    expect(codes(`class C { @storage('ns') @state x: u256; f(): External<void> { this.x = 1n; } }`)).toContain('JETH481');
  });

  it('gate: @storage needs exactly one non-empty string-literal namespace', () => {
    expect(codes(`class C { @storage() x: u256; get f(): External<u256> { return this.x; } }`).length).toBeGreaterThan(0);
    expect(codes(`class C { @storage('') x: u256; get f(): External<u256> { return this.x; } }`).length).toBeGreaterThan(0);
  });
});
