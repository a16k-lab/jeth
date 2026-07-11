// Diamond FINALIZABLE freeze lifecycle: every @diamond (any model) gets a synthesized owner-gated
// `freezeDiamond()` that permanently disables `diamondCut`, plus `isFrozen()`. This is the EIP-2535-blessed
// "deploy upgradeable, freeze later" immutability path (true born-frozen-at-deploy is not expressible because
// a FacetCut[] constructor param is gated, JETH302). The `_frozen` flag is appended to the diamond storage at
// a fresh slot (reads 0 when unused) and the diamondCut guard is a no-op while unfrozen, so a non-frozen
// diamond stays observably byte-identical to its reference (the existing diamond-array/packed/solidstate tests
// pass unchanged). Here we verify the freeze BEHAVIOR: the array model byte-identical to a solc diamond-3
// mirror carrying the same uint256 _frozen flag + guard (isFrozen, the non-owner gate, the raw _frozen slot,
// the cut-after-freeze Error("Diamond: diamond is frozen") revert, routing still works post-freeze), and that
// freeze disables the cut on the packed and solidstate models too.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { Address, hexToBytes, bytesToHex } from '@ethereumjs/util';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const STR = new Address(Buffer.from('33'.repeat(20), 'hex'));
const W = (b: bigint) => pad32(b);
const BI = (h: string) => (!h || h === '0x' ? 0n : BigInt(h));
const hx = (s: string) => hexToBytes(('0x' + s) as `0x${string}`);
const sel = (s: string) => functionSelector(s);
const dBase = BI('0x' + toHex(keccak('diamond.standard.diamond.storage')));
const P = (b: bigint) => pad32(b);
const b4w = (s: string) => s + '0'.repeat(56);
const encB4 = (s: string[]) => P(BigInt(s.length)) + s.map(b4w).join('');
const encT = (f: bigint, a: number, s: string[]) => P(f) + P(BigInt(a)) + P(0x60n) + encB4(s);
const encArr = (c: [bigint, number, string[]][]) => {
  const t = c.map((x) => encT(x[0], x[1], x[2]));
  let acc = c.length * 32;
  const o: string[] = [];
  for (const tt of t) { o.push(P(BigInt(acc))); acc += tt.length / 2; }
  return P(BigInt(c.length)) + o.join('') + t.join('');
};
const encCut = (c: [bigint, number, string[]][]) => {
  const ce = encArr(c);
  return P(0x60n) + P(0n) + P(BigInt(0x60 + ce.length / 2)) + ce + P(0n);
};
const cutSig = sel('diamondCut((address,uint8,bytes4[])[],address,bytes)');
const ret = (r: any) => (r.returnHex.startsWith('0x') ? r.returnHex.slice(2) : r.returnHex);

const CF = `@facet class CF { @storage('z') v: u256; inc(): External<void> { this.v += 1n; } get get(): External<u256> { return this.v; } }`;
const ARR = `@diamond('array') class D { constructor(o: address) { diamondInit(o); } }`;
const PK = `@diamond('packed') class D { constructor(o: address) { diamondInit(o); } }`;
const SS = `@diamond('solidstate') class D { constructor(o: address) { diamondInitSolidstate(o); } }`;
const SOL = `
library L { bytes32 constant DS=keccak256("diamond.standard.diamond.storage");
  struct FAP{address facetAddress;uint96 p;} struct FFS{bytes4[] s;uint256 fp;}
  struct DS_{mapping(bytes4=>FAP) s2f;mapping(address=>FFS) fs;address[] fa;mapping(bytes4=>bool) si;address owner;uint256 frozen;}
  struct FacetCut{address facetAddress;uint8 action;bytes4[] functionSelectors;}
  event DiamondCut(FacetCut[] c,address i,bytes d);
  function s() internal pure returns(DS_ storage d){ bytes32 p=DS; assembly{ d.slot:=p } }
  function cod(address a) internal view returns(uint256 n){ assembly{ n:=extcodesize(a) } }
  function cut(FacetCut[] memory c) internal { DS_ storage d=s(); for(uint i;i<c.length;i++){ if(c[i].action==0){ require(c[i].functionSelectors.length>0); require(c[i].facetAddress!=address(0)); uint96 sp=uint96(d.fs[c[i].facetAddress].s.length);
    if(sp==0){ require(cod(c[i].facetAddress)>0); d.fs[c[i].facetAddress].fp=d.fa.length; d.fa.push(c[i].facetAddress); }
    for(uint j;j<c[i].functionSelectors.length;j++){ bytes4 se=c[i].functionSelectors[j]; require(d.s2f[se].facetAddress==address(0)); d.s2f[se].p=sp; d.fs[c[i].facetAddress].s.push(se); d.s2f[se].facetAddress=c[i].facetAddress; sp++; } } } emit DiamondCut(c,address(0),""); } }
contract D { constructor(address o){ L.s().owner=o; }
  function owner() external view returns(address){ return L.s().owner; }
  function isFrozen() external view returns(bool){ return L.s().frozen != 0; }
  function freezeDiamond() external { require(msg.sender==L.s().owner,"LibDiamond: Must be contract owner"); L.s().frozen=1; }
  function diamondCut(L.FacetCut[] calldata c, address, bytes calldata) external { require(msg.sender==L.s().owner,"LibDiamond: Must be contract owner"); require(L.s().frozen==0,"Diamond: diamond is frozen"); L.FacetCut[] memory m=new L.FacetCut[](c.length); for(uint i;i<c.length;i++){ m[i]=c[i]; } L.cut(m); }
  fallback() external payable { address f=L.s().s2f[msg.sig].facetAddress; require(f!=address(0),"Diamond: Function does not exist"); assembly{ calldatacopy(0,0,calldatasize()) let r:=delegatecall(gas(),f,0,calldatasize(),0,0) returndatacopy(0,0,returndatasize()) switch r case 0 {revert(0,returndatasize())} default {return(0,returndatasize())} } }
  receive() external payable {} }
contract CF { struct St{uint256 v;} function _s() internal pure returns(St storage s){ bytes32 l=keccak256(abi.encode(uint256(keccak256("z"))-1))&~bytes32(uint256(0xff)); assembly{ s.slot:=l } }
  function inc() external { _s().v+=1; } function get() external view returns(uint256){ return _s().v; } }`;

async function arrRun(kind: 'J' | 'S') {
  const h = await Harness.create();
  for (const a of [me, STR]) await h.fund(a, 10n ** 20n);
  const cf = kind === 'J' ? await h.deploy(compile(CF, { fileName: 'c.jeth' }).creationBytecode, { caller: me }) : await h.deploy(compileSolidity(SPDX + SOL, 'CF').creation, { caller: me });
  const dia = kind === 'J' ? await h.deploy(compile(ARR, { fileName: 'd.jeth' }).creationBytecode + W(BI(me.toString())), { caller: me }) : await h.deploy(compileSolidity(SPDX + SOL, 'D').creation + W(BI(me.toString())), { caller: me });
  const call = (d: string, c = me) => h.call(dia, '0x' + d, { caller: c });
  await call(cutSig + encCut([[BI(cf.toString()), 0, [sel('inc()'), sel('get()')]]]));
  await call(sel('inc()'));
  const rd = async (slot: bigint) => BI(bytesToHex(await h.evm.stateManager.getStorage(dia, hx(pad32(slot)))));
  const o: any = {};
  o.isFrozen0 = ret(await call(sel('isFrozen()')));
  const fzStr = await call(sel('freezeDiamond()'), STR);
  o.freezeNonOwner = ret(fzStr).slice(0, 8) + ':' + fzStr.success;
  await call(sel('freezeDiamond()'));
  o.isFrozen1 = ret(await call(sel('isFrozen()')));
  o.frozenSlot = (await rd(dBase + 5n)).toString();
  const cutAfter = await call(cutSig + encCut([[BI(cf.toString()), 0, [sel('foo()')]]]));
  o.cutAfterFreeze = ret(cutAfter) + ':' + cutAfter.success;
  o.routeAfter = BI((await call(sel('get()'))).returnHex).toString();
  return o;
}

async function behaviorRun(src: string) {
  const h = await Harness.create();
  for (const a of [me, STR]) await h.fund(a, 10n ** 20n);
  const cf = await h.deploy(compile(CF, { fileName: 'c.jeth' }).creationBytecode, { caller: me });
  const dia = await h.deploy(compile(src, { fileName: 'd.jeth' }).creationBytecode + W(BI(me.toString())), { caller: me });
  const call = (d: string, c = me) => h.call(dia, '0x' + d, { caller: c });
  await call(cutSig + encCut([[BI(cf.toString()), 0, [sel('inc()'), sel('get()')]]]));
  await call(sel('inc()'));
  const f0 = ret(await call(sel('isFrozen()')));
  const nonOwner = (await call(sel('freezeDiamond()'), STR)).success;
  await call(sel('freezeDiamond()'));
  const f1 = ret(await call(sel('isFrozen()')));
  const cutAfter = (await call(cutSig + encCut([[BI(cf.toString()), 0, [sel('foo()')]]]))).success;
  const route = BI((await call(sel('get()'))).returnHex).toString();
  return { f0, nonOwner, f1, cutAfter, route };
}

describe('diamond finalizable freeze (freezeDiamond / isFrozen)', () => {
  it('array model byte-identical to a solc diamond-3 mirror with the freeze flag', async () => {
    const [j, s] = [await arrRun('J'), await arrRun('S')];
    expect(j).toEqual(s);
    expect(BI('0x' + j.isFrozen0)).toBe(0n); // not frozen initially
    expect(j.freezeNonOwner).toContain(':false'); // non-owner freezeDiamond reverts
    expect(BI('0x' + j.isFrozen1)).toBe(1n); // frozen after
    expect(j.frozenSlot).toBe('1'); // raw _frozen slot
    expect(j.cutAfterFreeze).toContain('08c379a0'); // Error(string) "Diamond: diamond is frozen"
    expect(j.cutAfterFreeze).toContain(':false');
    expect(j.routeAfter).toBe('1'); // routing still works after freeze
  });

  it('freeze disables diamondCut on the packed model (routing preserved)', async () => {
    const r = await behaviorRun(PK);
    expect(BI('0x' + r.f0)).toBe(0n);
    expect(r.nonOwner).toBe(false);
    expect(BI('0x' + r.f1)).toBe(1n);
    expect(r.cutAfter).toBe(false);
    expect(r.route).toBe('1');
  });

  it('freeze disables diamondCut on the solidstate model (routing preserved)', async () => {
    const r = await behaviorRun(SS);
    expect(BI('0x' + r.f0)).toBe(0n);
    expect(r.nonOwner).toBe(false);
    expect(BI('0x' + r.f1)).toBe(1n);
    expect(r.cutAfter).toBe(false);
    expect(r.route).toBe('1');
  });
});
