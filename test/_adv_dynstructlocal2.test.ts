// ADVERSARIAL: dynamic-field struct MEMORY local extensions (write + copy + alias).
// Differential vs solc; byte-identical returndata, success parity, and raw storage slots.
// Focus on the thin areas of the existing two tests:
//  - aliasing chains (let e=d; let g=e) with mixed value+bytes writes, read BOTH d and e/g
//  - DIRTY calldata struct value fields (u8/u64/i16/i8/address/bool/bytes4 with junk high bits):
//    solc VALIDATES on copy-to-memory -> revert; JETH must match revert vs success exactly
//  - multi-dynamic D{u256;string;bytes;u64} copied from storage / mapping / array / calldata,
//    write each bytes field, re-point repeatedly, head-offset correctness
//  - storage INDEPENDENCE: copy this.st, mutate the local, return d AND re-read this.st (slots)
//  - narrow/signed/bytesN/address value fields constructed/copied/written, returned whole
//  - empty/1/31/32/33/65/100-byte payloads in every position and op
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const hx = (s: string) => Buffer.from(s, 'utf8').toString('hex');
const encStr = (s: string) => { const h = hx(s); return pad(BigInt(h.length / 2)) + h.padEnd(Math.ceil(h.length / 64) * 64, '0'); };

// payload zoo: empty / 1 / 31 / 32 / 33 / 65 / 100 bytes
const S0 = '';
const S1 = 'x';
const S31 = 'a'.repeat(31);
const S32 = 'b'.repeat(32);
const S33 = 'c'.repeat(33);
const S65 = 'd'.repeat(65);
const S100 = 'e'.repeat(100);
const ALL = [S0, S1, S31, S32, S33, S65, S100];

// ---- JETH / SOL sources ---------------------------------------------------
const JETH = `
@struct class D { a: u256; s: string; }
@struct class D4 { a: u256; s: string; b: bytes; n: u64; }
@struct class DN { x: u8; y: i16; z: address; w: bytes4; flag: bool; s: string; }
@contract class C {
  @state st: D;
  @state m: mapping<address, D4>;
  @state recs: D4[];
  @state st4: D4;

  @external seedSt(av: u256, s: string): void { this.st = D(av, s); }
  @external seedSt4(av: u256, s: string, b: bytes, n: u64): void { this.st4 = D4(av, s, b, n); }
  @external seedMap(av: u256, s: string, b: bytes, n: u64): void { this.m[address(0xbeefn)] = D4(av, s, b, n); }
  @external seedRec(av: u256, s: string, b: bytes, n: u64): void { this.recs.push(D4(av, s, b, n)); }

  // storage independence: mutate copy, return it; getStA/getStS re-read storage afterward
  @external @view copyMutBoth(nv: u256, ns: string): D { let d: D = this.st; d.a = nv; d.s = ns; return d; }
  @external @view getStA(): u256 { return this.st.a; }
  @external @view getStS(): string { return this.st.s; }

  // alias chains
  @external @pure aliasChainBoth(av: u256, s: string, ns: string, nv: u256): D {
    let d: D = D(av, s); let e: D = d; let g: D = e; g.a = nv; g.s = ns; return d;
  }
  // mutate through alias, then return the ALIAS (should equal d too)
  @external @pure aliasReturnE(av: u256, s: string, ns: string): D {
    let d: D = D(av, s); let e: D = d; e.s = ns; e.a = 7n; return e;
  }
  // write value field on alias, write bytes on original, return e
  @external @pure aliasCross(av: u256, s: string, ns: string, nv: u256): D {
    let d: D = D(av, s); let e: D = d; d.s = ns; e.a = nv; return e;
  }

  // D4 from each storage source, returned whole
  @external @view from4St(): D4 { let d: D4 = this.st4; return d; }
  @external @view from4Map(): D4 { let d: D4 = this.m[address(0xbeefn)]; return d; }
  @external @view from4Rec(): D4 { let d: D4 = this.recs[0n]; return d; }
  // D4 copy then write each bytes/string field, plus value fields
  @external @view from4StWrite(ns: string, nb: bytes, nv: u256, nn: u64): D4 {
    let d: D4 = this.st4; d.s = ns; d.b = nb; d.a = nv; d.n = nn; return d;
  }
  // repeated re-point of the same bytes field
  @external @pure repoint(av: u256, s1: string, s2: string, s3: string): D {
    let d: D = D(av, s1); d.s = s2; d.s = s3; return d;
  }
  // D4 constructed, write bytes then string interleaved with value
  @external @pure d4ctorWrite(av: u256, s: string, b: bytes, n: u64, ns: string, nb: bytes): D4 {
    let d: D4 = D4(av, s, b, n); d.b = nb; d.s = ns; return d;
  }

  // calldata copy of D4 (dirty bytes fields validated; value field too)
  @external @pure from4Cd(x: D4): D4 { let d: D4 = x; return d; }
  // calldata copy of DN: narrow/signed/address/bytes4/bool value fields -> validation parity
  @external @pure fromDNcd(x: DN): DN { let d: DN = x; return d; }
  // construct DN with narrow fields, return whole
  @external @pure mkDN(x: u8, y: i16, z: address, w: bytes4, flag: bool, s: string): DN {
    let d: DN = DN(x, y, z, w, flag, s); return d;
  }
  // DN copy from calldata then mutate the string field
  @external @pure fromDNcdMut(x: DN, ns: string): DN { let d: DN = x; d.s = ns; return d; }

  // D4 alias: write bytes on the ORIGINAL, observe via the alias's bytes read (length + byte index)
  @external @view aliasD4Len(): u256 { let d: D4 = this.st4; let e: D4 = d; d.b = "ZZZ"; return e.b.length; }
  @external @view aliasD4Byte(i: u256): u8 { let d: D4 = this.st4; let e: D4 = d; d.b = "ABCDE"; return u8(e.b[i]); }
  // D4 alias: mutate through alias e (value + both dyn fields), return the ORIGINAL d
  @external @view aliasD4Cross(nv: u256, ns: string, nb: bytes): D4 {
    let d: D4 = this.st4; let e: D4 = d; e.a = nv; e.s = ns; e.b = nb; return d;
  }
  // calldata D4 OOB byte index after copy
  @external @pure cdByteAt(x: D4, i: u256): u8 { let d: D4 = x; return u8(d.b[i]); }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct D { uint256 a; string s; }
  struct D4 { uint256 a; string s; bytes b; uint64 n; }
  struct DN { uint8 x; int16 y; address z; bytes4 w; bool flag; string s; }
  D st;
  mapping(address => D4) m;
  D4[] recs;
  D4 st4;

  function seedSt(uint256 av, string calldata s) external { st = D(av, s); }
  function seedSt4(uint256 av, string calldata s, bytes calldata b, uint64 n) external { st4 = D4(av, s, b, n); }
  function seedMap(uint256 av, string calldata s, bytes calldata b, uint64 n) external { m[address(0xbeef)] = D4(av, s, b, n); }
  function seedRec(uint256 av, string calldata s, bytes calldata b, uint64 n) external { recs.push(D4(av, s, b, n)); }

  function copyMutBoth(uint256 nv, string calldata ns) external view returns (D memory) { D memory d = st; d.a = nv; d.s = ns; return d; }
  function getStA() external view returns (uint256) { return st.a; }
  function getStS() external view returns (string memory) { return st.s; }

  function aliasChainBoth(uint256 av, string calldata s, string calldata ns, uint256 nv) external pure returns (D memory) {
    D memory d = D(av, s); D memory e = d; D memory g = e; g.a = nv; g.s = ns; return d;
  }
  function aliasReturnE(uint256 av, string calldata s, string calldata ns) external pure returns (D memory) {
    D memory d = D(av, s); D memory e = d; e.s = ns; e.a = 7; return e;
  }
  function aliasCross(uint256 av, string calldata s, string calldata ns, uint256 nv) external pure returns (D memory) {
    D memory d = D(av, s); D memory e = d; d.s = ns; e.a = nv; return e;
  }

  function from4St() external view returns (D4 memory) { D4 memory d = st4; return d; }
  function from4Map() external view returns (D4 memory) { D4 memory d = m[address(0xbeef)]; return d; }
  function from4Rec() external view returns (D4 memory) { D4 memory d = recs[0]; return d; }
  function from4StWrite(string calldata ns, bytes calldata nb, uint256 nv, uint64 nn) external view returns (D4 memory) {
    D4 memory d = st4; d.s = ns; d.b = nb; d.a = nv; d.n = nn; return d;
  }
  function repoint(uint256 av, string calldata s1, string calldata s2, string calldata s3) external pure returns (D memory) {
    D memory d = D(av, s1); d.s = s2; d.s = s3; return d;
  }
  function d4ctorWrite(uint256 av, string calldata s, bytes calldata b, uint64 n, string calldata ns, bytes calldata nb) external pure returns (D4 memory) {
    D4 memory d = D4(av, s, b, n); d.b = nb; d.s = ns; return d;
  }

  function from4Cd(D4 calldata x) external pure returns (D4 memory) { D4 memory d = x; return d; }
  function fromDNcd(DN calldata x) external pure returns (DN memory) { DN memory d = x; return d; }
  function mkDN(uint8 x, int16 y, address z, bytes4 w, bool flag, string calldata s) external pure returns (DN memory) {
    DN memory d = DN(x, y, z, w, flag, s); return d;
  }
  function fromDNcdMut(DN calldata x, string calldata ns) external pure returns (DN memory) { DN memory d = x; d.s = ns; return d; }

  function aliasD4Len() external view returns (uint256) { D4 memory d = st4; D4 memory e = d; d.b = "ZZZ"; return e.b.length; }
  function aliasD4Byte(uint256 i) external view returns (uint8) { D4 memory d = st4; D4 memory e = d; d.b = "ABCDE"; return uint8(e.b[i]); }
  function aliasD4Cross(uint256 nv, string calldata ns, bytes calldata nb) external view returns (D4 memory) {
    D4 memory d = st4; D4 memory e = d; e.a = nv; e.s = ns; e.b = nb; return d;
  }
  function cdByteAt(D4 calldata x, uint256 i) external pure returns (uint8) { D4 memory d = x; return uint8(d.b[i]); }
}`;

describe('ADVERSARIAL dyn-struct memory local: write/copy/alias vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  async function seedBoth(data: string) { await jeth.call(aj, data); await sol.call(as, data); }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  // (uint256 a, string s)
  const cdUS = (sig: string, a: bigint, s: string) => '0x' + sel(sig) + pad(a) + pad(0x40n) + encStr(s);
  // (uint256 av, string s, string ns, uint256 nv): head [av][off_s=0x80][off_ns][nv]
  const cdUSSU = (sig: string, av: bigint, s: string, ns: string, nv: bigint) => {
    const t1 = encStr(s); const offNs = 0x80 + t1.length / 2;
    return '0x' + sel(sig) + pad(av) + pad(0x80n) + pad(BigInt(offNs)) + pad(nv) + t1 + encStr(ns);
  };
  // (uint256 av, string s, string ns): head [av][off_s=0x60][off_ns]
  const cdUSS = (sig: string, av: bigint, s: string, ns: string) => {
    const t1 = encStr(s); const offNs = 0x60 + t1.length / 2;
    return '0x' + sel(sig) + pad(av) + pad(0x60n) + pad(BigInt(offNs)) + t1 + encStr(ns);
  };

  it('alias chains (d->e->g): value+string mutation through the tail alias visible at the head', async () => {
    for (const s of ALL) for (const ns of [S0, S1, S33, S100]) {
      await eq(`aliasChainBoth(${s.length},${ns.length})`, cdUSSU('aliasChainBoth(uint256,string,string,uint256)', 11n, s, ns, 0xdeadn));
      await eq(`aliasReturnE(${s.length},${ns.length})`, cdUSS('aliasReturnE(uint256,string,string)', 5n, s, ns));
      await eq(`aliasCross(${s.length},${ns.length})`, cdUSSU('aliasCross(uint256,string,string,uint256)', 1n, s, ns, 0xc0ffeen));
    }
  });

  it('repeated re-point of one string field (short<->long<->empty)', async () => {
    for (const s1 of [S0, S31, S100]) for (const s2 of [S1, S32]) for (const s3 of ALL) {
      // (uint256 av, string s1, string s2, string s3): head [av][off1=0x80][off2][off3]
      const t1 = encStr(s1), t2 = encStr(s2);
      const off2 = 0x80 + t1.length / 2;
      const off3 = off2 + t2.length / 2;
      const data = '0x' + sel('repoint(uint256,string,string,string)') + pad(9n) + pad(0x80n) + pad(BigInt(off2)) + pad(BigInt(off3)) + t1 + t2 + encStr(s3);
      await eq(`repoint(${s1.length},${s2.length},${s3.length})`, data);
    }
  });

  // ---- D4 storage copy + writes ----
  // seed D4: (uint256 av, string s, bytes b, uint64 n): head [av][off_s=0x80][off_b][n]
  const seed4 = (sig: string, av: bigint, s: string, b: string, n: bigint) => {
    const t1 = encStr(s); const offB = 0x80 + t1.length / 2;
    return '0x' + sel(sig) + pad(av) + pad(0x80n) + pad(BigInt(offB)) + pad(n) + t1 + encStr(b);
  };

  it('D4 copy from storage / mapping / array element, returned whole', async () => {
    for (const [av, s, b, n] of [
      [1n, S1, S0, 0n], [M - 1n, S100, S33, 0xffffffffffffffffn], [0n, S0, S100, 42n], [7n, S32, S32, 1n], [3n, S33, S31, 9n],
    ] as const) {
      await seedBoth(seed4('seedSt4(uint256,string,bytes,uint64)', av, s, b, n));
      await seedBoth(seed4('seedMap(uint256,string,bytes,uint64)', av, s, b, n));
      await eq(`from4St(${s.length},${b.length})`, encodeCall(sel('from4St()'), []));
      await eq(`from4Map(${s.length},${b.length})`, encodeCall(sel('from4Map()'), []));
    }
    await seedBoth(seed4('seedRec(uint256,string,bytes,uint64)', 99n, S65, S33, 5n));
    await eq('from4Rec', encodeCall(sel('from4Rec()'), []));
  });

  it('D4 storage copy then write every field, returned whole', async () => {
    await seedBoth(seed4('seedSt4(uint256,string,bytes,uint64)', 4n, S31, S65, 3n));
    for (const ns of [S0, S1, S33]) for (const nb of [S0, S32, S100]) {
      // (string ns, bytes nb, uint256 nv, uint64 nn): head [off_ns=0x80][off_nb][nv][nn]
      const t1 = encStr(ns); const offNb = 0x80 + t1.length / 2;
      const data = '0x' + sel('from4StWrite(string,bytes,uint256,uint64)') + pad(0x80n) + pad(BigInt(offNb)) + pad(0x123n) + pad(7n) + t1 + encStr(nb);
      await eq(`from4StWrite(${ns.length},${nb.length})`, data);
    }
  });

  it('D4 constructed then write bytes+string interleaved', async () => {
    for (const s of [S0, S33]) for (const b of [S1, S100]) for (const ns of [S0, S65]) for (const nb of [S31, S0]) {
      // (uint256 av, string s, bytes b, uint64 n, string ns, bytes nb): head 6 words off_s=0xc0
      const t_s = encStr(s), t_b = encStr(b), t_ns = encStr(ns);
      const offS = 0xc0;
      const offB = offS + t_s.length / 2;
      const offNs = offB + t_b.length / 2;
      const offNb = offNs + t_ns.length / 2;
      const data = '0x' + sel('d4ctorWrite(uint256,string,bytes,uint64,string,bytes)')
        + pad(8n) + pad(BigInt(offS)) + pad(BigInt(offB)) + pad(0x55n) + pad(BigInt(offNs)) + pad(BigInt(offNb))
        + t_s + t_b + t_ns + encStr(nb);
      await eq(`d4ctorWrite(${s.length},${b.length},${ns.length},${nb.length})`, data);
    }
  });

  // ---- calldata D4 copy: clean + DIRTY value field (uint64 n with high bits) ----
  it('D4 from calldata: clean and DIRTY uint64 field (validation parity)', async () => {
    // calldata D4 = (uint256,string,bytes,uint64) dynamic -> selector + off(0x20) + tuple
    const mk = (av: bigint, s: string, b: string, nWord: bigint) => {
      const t1 = encStr(s); const offS = 0x80; const offB = offS + t1.length / 2;
      // tuple head: [av][off_s][off_b][n], offsets relative to tuple base
      const tuple = pad(av) + pad(BigInt(offS)) + pad(BigInt(offB)) + pad(nWord) + t1 + encStr(b);
      return '0x' + sel('from4Cd((uint256,string,bytes,uint64))') + pad(0x20n) + tuple;
    };
    for (const [s, b] of [[S0, S0], [S1, S100], [S33, S31], [S100, S65]] as const) {
      await eq(`from4Cd clean(${s.length},${b.length})`, mk(7n, s, b, 0xffffffffffffffffn)); // max valid u64
      await eq(`from4Cd DIRTY n(${s.length},${b.length})`, mk(7n, s, b, (1n << 64n))); // one bit too high -> solc reverts
      await eq(`from4Cd DIRTY n hi`, mk(7n, s, b, M - 1n)); // all high bits set
    }
  });

  // ---- DN: narrow/signed/address/bytes4/bool value fields ----
  // DN = (uint8,int16,address,bytes4,bool,string) dynamic.
  // The string is the only dynamic field; head = 6 words, off_s = 0xc0.
  const dnTuple = (x: bigint, y: bigint, z: bigint, w: bigint, flag: bigint, s: string) =>
    pad(x) + pad(y) + pad(z) + pad(w) + pad(flag) + pad(0xc0n) + encStr(s);
  const cdDN = (sig: string, x: bigint, y: bigint, z: bigint, w: bigint, flag: bigint, s: string) =>
    '0x' + sel(sig) + pad(0x20n) + dnTuple(x, y, z, w, flag, s);

  it('DN constructed whole (narrow/signed/address/bytes4/bool)', async () => {
    // mkDN(x,y,z,w,flag,s): static value args inline, string last; head off_s=0xc0
    const mk = (x: bigint, y: bigint, z: bigint, w: bigint, flag: bigint, s: string) =>
      '0x' + sel('mkDN(uint8,int16,address,bytes4,bool,string)') + pad(x) + pad(y) + pad(z) + pad(w) + pad(flag) + pad(0xc0n) + encStr(s);
    const i16 = (v: bigint) => ((v % M) + M) % M; // sign-extended 256-bit of an int16 value
    for (const s of [S0, S1, S33, S100]) {
      await eq(`mkDN pos(${s.length})`, mk(255n, i16(1234n), 0xabcdef1234567890abcdef1234567890abcdef12n, BigInt('0xdeadbeef') << (28n * 8n), 1n, s));
      await eq(`mkDN neg(${s.length})`, mk(0n, i16(-5n), 0n, 0n, 0n, s)); // int16 = -5 (clean sign-extension)
    }
  });

  it('DN from calldata: CLEAN value fields (validation parity)', async () => {
    for (const s of [S0, S1, S33, S100]) {
      // clean: u8=200, int16=-7 (sign-extended), address=20 bytes, bytes4 left-aligned, bool=1
      const i16neg = ((M - 7n) % M); // -7 as sign-extended 256-bit
      await eq(`fromDNcd clean(${s.length})`,
        cdDN('fromDNcd((uint8,int16,address,bytes4,bool,string))',
          200n, i16neg, 0x1234567890abcdef1234567890abcdef12345678n, BigInt('0xcafebabe') << (28n * 8n), 1n, s));
    }
  });

  it('DN from calldata: DIRTY value fields each independently (revert parity)', async () => {
    const cleanX = 200n, cleanY = (M - 7n) % M, cleanZ = 0x1234n, cleanW = BigInt('0xcafebabe') << (28n * 8n), cleanFlag = 1n;
    const s = S33;
    const cases: [string, bigint, bigint, bigint, bigint, bigint][] = [
      ['dirty u8 (high byte set)', 0x1ffn, cleanY, cleanZ, cleanW, cleanFlag],
      ['dirty u8 (full word)', M - 1n, cleanY, cleanZ, cleanW, cleanFlag],
      ['dirty int16 (not sign-extended)', cleanX, 0x10000n, cleanZ, cleanW, cleanFlag],
      ['dirty int16 (high junk on positive)', cleanX, 0xff0001n, cleanZ, cleanW, cleanFlag],
      ['dirty int16 (wrong sign-ext)', cleanX, (M - 0x20000n) % M, cleanZ, cleanW, cleanFlag],
      ['dirty address (high 96 bits)', cleanX, cleanY, (1n << 160n) | 0x1234n, cleanW, cleanFlag],
      ['dirty bytes4 (low bytes nonzero)', cleanX, cleanY, cleanZ, (BigInt('0xcafebabe') << (28n * 8n)) | 1n, cleanFlag],
      ['dirty bool (=2)', cleanX, cleanY, cleanZ, cleanW, 2n],
      ['dirty bool (huge)', cleanX, cleanY, cleanZ, cleanW, M - 1n],
    ];
    for (const [label, x, y, z, w, flag] of cases) {
      await eq(label, cdDN('fromDNcd((uint8,int16,address,bytes4,bool,string))', x, y, z, w, flag, s));
    }
  });

  it('DN from calldata then mutate string field (clean inputs, all payloads)', async () => {
    for (const s of ALL) for (const ns of [S0, S1, S100]) {
      // fromDNcdMut(x, ns): outer head [off_x=0x40][off_ns], then x tuple, then ns
      const xt = dnTuple(7n, 3n, 0x55n, BigInt('0xaabbccdd') << (28n * 8n), 1n, s);
      const offNs = 0x40 + xt.length / 2;
      const data = '0x' + sel('fromDNcdMut((uint8,int16,address,bytes4,bool,string),string)')
        + pad(0x40n) + pad(BigInt(offNs)) + xt + encStr(ns);
      await eq(`fromDNcdMut(${s.length},${ns.length})`, data);
    }
  });

  // ---- storage independence: mutate the copy must NOT touch this.st ----
  it('storage independence: copy this.st, mutate local, storage slots unchanged', async () => {
    for (const [av, s, nv, ns] of [
      [42n, S31, 0x999n, S100], [7n, S100, 0n, S0], [M - 1n, S0, 1n, S33],
    ] as const) {
      await seedBoth(cdUS('seedSt(uint256,string)', av, s));
      // call copyMutBoth, compare returndata
      await eq(`copyMutBoth(${s.length}->${ns.length})`, cdUS('copyMutBoth(uint256,string)', nv, ns));
      // now confirm storage is unchanged on BOTH sides (re-read via getters AND raw slots)
      await eq('getStA after copyMut', encodeCall(sel('getStA()'), []));
      await eq('getStS after copyMut', encodeCall(sel('getStS()'), []));
      // raw storage parity for st (slot 0 = a, slot 1 = string header) -- st is slot 0/1
      for (const slot of [0n, 1n]) {
        const jv = await readSlot(jeth, aj, slot);
        const sv = await readSlot(sol, as, slot);
        expect(jv, `raw slot ${slot} after copyMut(av=${av},s=${s.length})`).toBe(sv);
      }
    }
  });

  it('D4 alias: write bytes on original, read length/byte via the alias (shared image)', async () => {
    await seedBoth(seed4('seedSt4(uint256,string,bytes,uint64)', 1n, S1, S100, 2n));
    await eq('aliasD4Len', encodeCall(sel('aliasD4Len()'), []));
    for (let i = 0n; i < 6n; i++) await eq(`aliasD4Byte(${i})`, encodeCall(sel('aliasD4Byte(uint256)'), [i]));
    await eq('aliasD4Byte OOB', encodeCall(sel('aliasD4Byte(uint256)'), [5n])); // "ABCDE" len 5 -> index 5 OOB
  });

  it('D4 alias cross: mutate value+string+bytes via alias e, return original d', async () => {
    for (const _ of [[S0, S0], [S33, S100], [S100, S31]] as const) {
      await seedBoth(seed4('seedSt4(uint256,string,bytes,uint64)', 9n, S31, S65, 3n));
      for (const ns of [S0, S1, S65]) for (const nb of [S0, S32, S100]) {
        // aliasD4Cross(nv, ns, nb): head [nv][off_ns=0x60][off_nb]
        const t1 = encStr(ns); const offNb = 0x60 + t1.length / 2;
        const data = '0x' + sel('aliasD4Cross(uint256,string,bytes)') + pad(0x321n) + pad(0x60n) + pad(BigInt(offNb)) + t1 + encStr(nb);
        await eq(`aliasD4Cross(${ns.length},${nb.length})`, data);
      }
    }
  });

  it('calldata D4 byte index after copy (in-bounds + OOB Panic parity)', async () => {
    const mk = (b: string, i: bigint) => {
      const s = S1; const t1 = encStr(s); const offS = 0x80; const offB = offS + t1.length / 2;
      const tuple = pad(7n) + pad(BigInt(offS)) + pad(BigInt(offB)) + pad(0n) + t1 + encStr(b);
      const offX = 0x40; // outer head [off_x=0x40][i]
      // outer: [off_x][i][tuple]
      return '0x' + sel('cdByteAt((uint256,string,bytes,uint64),uint256)') + pad(BigInt(offX)) + pad(i) + tuple;
    };
    for (let i = 0n; i < 6n; i++) await eq(`cdByteAt("ABCDE",${i})`, mk('ABCDE', i));
    await eq('cdByteAt OOB', mk('ABC', 9n));
  });

  it('calldata struct copy with MALFORMED dynamic offset (revert parity)', async () => {
    // from4Cd with the string offset pointing past calldata end -> solc reverts; JETH must too.
    // tuple = [av][off_s=BAD][off_b][n] ... we make off_s huge.
    const bad = (offS: bigint) => {
      const t1 = encStr(S1); const offB = 0x80n + BigInt(t1.length / 2);
      const tuple = pad(7n) + pad(offS) + pad(offB) + pad(0n) + t1 + encStr(S1);
      return '0x' + sel('from4Cd((uint256,string,bytes,uint64))') + pad(0x20n) + tuple;
    };
    await eq('from4Cd off_s huge', bad(1n << 200n));
    await eq('from4Cd off_s = 0xffffffff', bad(0xffffffffn));
    // truncated calldata: declare a long string length but provide no data
    const truncated = () => {
      const tuple = pad(7n) + pad(0x80n) + pad(0xa0n) + pad(0n) + pad(0x100n) /* len=256 but no data */;
      return '0x' + sel('from4Cd((uint256,string,bytes,uint64))') + pad(0x20n) + tuple;
    };
    await eq('from4Cd truncated string', truncated());
  });

  // ---- raw-slot parity after seeding D4 into storage (sanity that copy source is identical) ----
  it('raw-slot parity after seedSt4 (so storage copy source matches solc)', async () => {
    for (const [av, s, b, n] of [[5n, S33, S65, 9n], [0n, S0, S0, 0n], [1n, S100, S31, 0xffffn]] as const) {
      await seedBoth(seed4('seedSt4(uint256,string,bytes,uint64)', av, s, b, n));
      // st4 occupies slots 4.. (D at 0/1, m at 2, recs at 3, st4 at 4). compare first few slots.
      for (const slot of [4n, 5n, 6n, 7n]) {
        const jv = await readSlot(jeth, aj, slot);
        const sv = await readSlot(sol, as, slot);
        expect(jv, `st4 raw slot ${slot} (s=${s.length},b=${b.length})`).toBe(sv);
      }
      await eq(`from4St roundtrip(${s.length},${b.length})`, encodeCall(sel('from4St()'), []));
    }
  });
});
