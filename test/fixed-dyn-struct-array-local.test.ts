// Lift #4: a FIXED-outer array of DYNAMIC structs `Arr<In,N>` (In a dynamic-field @struct, e.g.
// { s: string; n: u256 }) as a MEMORY LOCAL. Its image is N absolute-pointer words (NO [len] header),
// each pointing to a per-element dyn-struct image (value fields inline, bytes/string a head pointer) -
// the SAME pointer-headed image `In[]` and the @external In[N] calldata->image builder already use.
// Byte-identical to solc 0.8.35 across: build-from-literal, element field read a[i].s / a[i].n, element
// write a[i] = In(...), field write a[i].s = "...", whole-element bind `let e: In = a[i]`, for-of, whole
// return, abi.encode(a), .length, N=1..3, empty/short/>31-byte strings, an In with a 3rd bytes field, a
// nested Arr<Arr<In,N>,M>, and the struct-FIELD form D{items:Arr<In,N>;k}. Reads from a storage Arr<In,N>
// (bind + direct) are byte-identical too; the memory->storage COPY (`this.fa = a`) is a clean JETH467
// reject, mirroring solc's legacy pipeline (UnimplementedFeatureError). OOB is Panic 0x32.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => functionSelector(s);
function codes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}
// ABI-decode a single `string` sole return (head [0x20] + [len][data]).
function decodeString(hex: string): string {
  const b = Buffer.from(hex.replace(/^0x/, ''), 'hex');
  const len = Number(BigInt('0x' + b.subarray(0x20, 0x40).toString('hex')));
  return b.subarray(0x40, 0x40 + len).toString('utf8');
}
function decodeU256(hex: string): bigint {
  return BigInt('0x' + hex.replace(/^0x/, '').slice(0, 64));
}

describe('fixed-outer array of dynamic structs Arr<In,N> memory local (Lift #4) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const J = `type In = { s: string; n: u256 };
type D = { items: Arr<In,2>; k: u256 };
class C {
  get rdS(i: u256): External<string> { let a: Arr<In,3> = [In("first_element_string_over_thirty_two_bytes!",11n),In("two",22n),In("",33n)]; return a[i].s; }
  get rdN(i: u256): External<u256> { let a: Arr<In,3> = [In("aa",11n),In("bb",22n),In("cc",33n)]; return a[i].n; }
  get welem(): External<string> { let a: Arr<In,2> = [In("x",1n),In("y",2n)]; a[1n] = In("replaced_with_a_long_string_over_32_bytes!",99n); return a[1n].s; }
  get wfield(): External<u256> { let a: Arr<In,2> = [In("x",1n),In("y",2n)]; a[0n].s = "changed"; a[0n].n = 555n; return a[0n].n; }
  get len(): External<u256> { let a: Arr<In,2> = [In("x",1n),In("y",2n)]; return a.length; }
  get sumForOf(): External<u256> { let a: Arr<In,3> = [In("a",5n),In("b",6n),In("c",7n)]; let t: u256 = 0n; for (const e of a) { t = t + e.n; } return t; }
  get bindElem(i: u256): External<string> { let a: Arr<In,3> = [In("p",1n),In("this_element_is_definitely_over_thirty_two",2n),In("r",3n)]; let e: In = a[i]; return e.s; }
  get whole(): External<Arr<In,2>> { let a: Arr<In,2> = [In("hello",1n),In("a-string-that-is-quite-a-bit-longer-than-32",2n)]; return a; }
  get enc(): External<bytes> { let a: Arr<In,2> = [In("hello",1n),In("a-string-that-is-quite-a-bit-longer-than-32",2n)]; return abi.encode(a); }
  get sfRead(i: u256): External<string> { let d: D = D([In("struct_field_element_string_over_32_bytes!!",1n),In("bb",2n)], 7n); return d.items[i].s; }
  get sfSum(): External<u256> { let d: D = D([In("a",10n),In("bb",20n)], 7n); return d.items[0n].n + d.items[1n].n + d.k; }
  get sfEnc(): External<bytes> { let d: D = D([In("a",10n),In("bb",20n)], 7n); return abi.encode(d); }
  get sfWhole(): External<D> { let d: D = D([In("a",10n),In("bb",20n)], 7n); return d; }
  get nested(i: u256, j: u256): External<string> { let a: Arr<Arr<In,2>,2> = [[In("aa",1n),In("bb",2n)],[In("cc_nested_element_string_over_thirty_two!",3n),In("dd",4n)]]; return a[i][j].s; }
  fa: Arr<In,2>;
  seed(): External<void> { this.fa[0n].s = "storage_seeded_element_over_thirty_two_bytes"; this.fa[0n].n = 111n; this.fa[1n].s = "one"; this.fa[1n].n = 222n; }
  get stDirect(i: u256): External<string> { return this.fa[i].s; }
  get stBind(i: u256): External<string> { let m: Arr<In,2> = this.fa; return m[i].s; }
  get stBindN(i: u256): External<u256> { let m: Arr<In,2> = this.fa; return m[i].n; }
}`;
  const So = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  struct In { string s; uint256 n; }
  struct D { In[2] items; uint256 k; }
  function rdS(uint256 i) external pure returns (string memory) { In[3] memory a = [In("first_element_string_over_thirty_two_bytes!",11),In("two",22),In("",33)]; return a[i].s; }
  function rdN(uint256 i) external pure returns (uint256) { In[3] memory a = [In("aa",11),In("bb",22),In("cc",33)]; return a[i].n; }
  function welem() external pure returns (string memory) { In[2] memory a = [In("x",1),In("y",2)]; a[1] = In("replaced_with_a_long_string_over_32_bytes!",99); return a[1].s; }
  function wfield() external pure returns (uint256) { In[2] memory a = [In("x",1),In("y",2)]; a[0].s = "changed"; a[0].n = 555; return a[0].n; }
  function len() external pure returns (uint256) { In[2] memory a = [In("x",1),In("y",2)]; return a.length; }
  function sumForOf() external pure returns (uint256) { In[3] memory a = [In("a",5),In("b",6),In("c",7)]; uint256 t=0; for(uint256 i=0;i<3;i++){t+=a[i].n;} return t; }
  function bindElem(uint256 i) external pure returns (string memory) { In[3] memory a = [In("p",1),In("this_element_is_definitely_over_thirty_two",2),In("r",3)]; In memory e = a[i]; return e.s; }
  function whole() external pure returns (In[2] memory) { In[2] memory a = [In("hello",1),In("a-string-that-is-quite-a-bit-longer-than-32",2)]; return a; }
  function enc() external pure returns (bytes memory) { In[2] memory a = [In("hello",1),In("a-string-that-is-quite-a-bit-longer-than-32",2)]; return abi.encode(a); }
  function sfRead(uint256 i) external pure returns (string memory) { D memory d = D([In("struct_field_element_string_over_32_bytes!!",1),In("bb",2)], 7); return d.items[i].s; }
  function sfSum() external pure returns (uint256) { D memory d = D([In("a",10),In("bb",20)], 7); return d.items[0].n + d.items[1].n + d.k; }
  function sfEnc() external pure returns (bytes memory) { D memory d = D([In("a",10),In("bb",20)], 7); return abi.encode(d); }
  function sfWhole() external pure returns (D memory) { D memory d = D([In("a",10),In("bb",20)], 7); return d; }
  function nested(uint256 i, uint256 j) external pure returns (string memory) { In[2][2] memory a = [[In("aa",1),In("bb",2)],[In("cc_nested_element_string_over_thirty_two!",3),In("dd",4)]]; return a[i][j].s; }
  In[2] fa;
  function seed() external { fa[0].s = "storage_seeded_element_over_thirty_two_bytes"; fa[0].n = 111; fa[1].s = "one"; fa[1].n = 222; }
  function stDirect(uint256 i) external view returns (string memory) { return fa[i].s; }
  function stBind(uint256 i) external view returns (string memory) { In[2] memory m = fa; return m[i].s; }
  function stBindN(uint256 i) external view returns (uint256) { In[2] memory m = fa; return m[i].n; }
}`;

  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(So, 'C').creation);
  });
  const cmp = async (data: string, label: string) => {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, label).toBe(s.returnHex);
    return j;
  };

  it('element field reads a[i].s / a[i].n byte-identical + concrete values', async () => {
    const r0 = await cmp('0x' + sel('rdS(uint256)') + pad32(0n), 'rdS[0]');
    expect(decodeString(r0.returnHex)).toBe('first_element_string_over_thirty_two_bytes!');
    const r2 = await cmp('0x' + sel('rdS(uint256)') + pad32(2n), 'rdS[2]');
    expect(decodeString(r2.returnHex)).toBe('');
    const rn = await cmp('0x' + sel('rdN(uint256)') + pad32(1n), 'rdN[1]');
    expect(decodeU256(rn.returnHex)).toBe(22n);
  });
  it('OOB index Panic 0x32 byte-identical', async () => {
    await cmp('0x' + sel('rdS(uint256)') + pad32(3n), 'rdS[3] OOB');
    await cmp('0x' + sel('rdN(uint256)') + pad32(99n), 'rdN[99] OOB');
  });
  it('element write a[i] = In(...) + field write a[i].s / a[i].n byte-identical', async () => {
    const w = await cmp('0x' + sel('welem()'), 'welem');
    expect(decodeString(w.returnHex)).toBe('replaced_with_a_long_string_over_32_bytes!');
    const f = await cmp('0x' + sel('wfield()'), 'wfield');
    expect(decodeU256(f.returnHex)).toBe(555n);
  });
  it('.length + for-of + whole-element bind byte-identical + concrete', async () => {
    const l = await cmp('0x' + sel('len()'), 'len');
    expect(decodeU256(l.returnHex)).toBe(2n);
    const s = await cmp('0x' + sel('sumForOf()'), 'sumForOf');
    expect(decodeU256(s.returnHex)).toBe(18n);
    const b = await cmp('0x' + sel('bindElem(uint256)') + pad32(1n), 'bindElem[1]');
    expect(decodeString(b.returnHex)).toBe('this_element_is_definitely_over_thirty_two');
  });
  it('whole return + abi.encode(a) byte-identical', async () => {
    await cmp('0x' + sel('whole()'), 'whole');
    await cmp('0x' + sel('enc()'), 'enc');
  });
  it('struct-field D{items:Arr<In,2>;k} read / sum / whole return / abi.encode byte-identical', async () => {
    const r = await cmp('0x' + sel('sfRead(uint256)') + pad32(0n), 'sfRead[0]');
    expect(decodeString(r.returnHex)).toBe('struct_field_element_string_over_32_bytes!!');
    const s = await cmp('0x' + sel('sfSum()'), 'sfSum');
    expect(decodeU256(s.returnHex)).toBe(37n); // 10 + 20 + 7
    await cmp('0x' + sel('sfEnc()'), 'sfEnc');
    await cmp('0x' + sel('sfWhole()'), 'sfWhole');
  });
  it('nested Arr<Arr<In,2>,2> element field read byte-identical', async () => {
    const r = await cmp('0x' + sel('nested(uint256,uint256)') + pad32(1n) + pad32(0n), 'nested[1][0]');
    expect(decodeString(r.returnHex)).toBe('cc_nested_element_string_over_thirty_two!');
  });
  it('storage Arr<In,2> direct read + bind-from-storage byte-identical (seed via native writes)', async () => {
    await jeth.call(aj, '0x' + sel('seed()'));
    await sol.call(as, '0x' + sel('seed()'));
    const d = await cmp('0x' + sel('stDirect(uint256)') + pad32(0n), 'stDirect[0]');
    expect(decodeString(d.returnHex)).toBe('storage_seeded_element_over_thirty_two_bytes');
    const b = await cmp('0x' + sel('stBind(uint256)') + pad32(0n), 'stBind[0]');
    expect(decodeString(b.returnHex)).toBe('storage_seeded_element_over_thirty_two_bytes');
    const bn = await cmp('0x' + sel('stBindN(uint256)') + pad32(1n), 'stBindN[1]');
    expect(decodeU256(bn.returnHex)).toBe(222n);
  });

  it('memory Arr<In,N> -> storage COPY is a clean JETH467 reject (matches solc legacy UnimplementedFeature)', () => {
    const src = `type In = { s: string; n: u256 };
class C { fa: Arr<In,2>; f(): External<void> { let a: Arr<In,2> = [In("x",1n),In("y",2n)]; this.fa = a; } }`;
    expect(codes(src)).toContain('JETH467');
    // solc's legacy pipeline rejects the same copy (UnimplementedFeatureError), so JETH must too.
    let solcOk = false;
    try {
      compileSolidity(
        `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C { struct In { string s; uint256 n; } In[2] fa;
  function f() external { In[2] memory a = [In("x",1),In("y",2)]; fa = a; } }`,
        'C',
      );
      solcOk = true;
    } catch {
      solcOk = false;
    }
    expect(solcOk, 'solc legacy also rejects the mem->storage Arr<In,N> copy').toBe(false);
  });
});
