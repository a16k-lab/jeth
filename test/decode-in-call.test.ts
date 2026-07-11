// Phase 6: a `decode` field inside the external-call options object, so addr.call({...})/staticcall({...})
// return the decoded value (or tuple) directly:
//   let s: string = addr.staticcall({ data, success: {...}, decode: string });
//   let [a, b]: [u256, address] = addr.staticcall({ data, success: {...}, decode: [u256, address] });
// This is exact sugar for addr.call({...}).decode(T): it wraps the call's bytes result in the SAME
// abi.decode codec (already verified byte-identical to solc in abi-decode-builtin.test.ts). These tests
// prove (1) the in-object form produces byte-identical CREATION BYTECODE to the chained .decode form, and
// (2) it is byte-identical to solc cross-contract, plus the accept/reject rules.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const P = (n: bigint) => pad32(n);

function jethAccepts(src: string): boolean {
  try {
    compile(src, { fileName: 'C.jeth' });
    return true;
  } catch {
    return false;
  }
}
function jethError(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return (e.diagnostics ?? []).map((d: any) => d.code);
  }
}

/** Deploy a JETH caller+target and a solc caller+target with matching external signatures; for each
 *  (sig) call both with the same calldata (the target address as the sole arg) and diff success+returndata. */
async function rtCross(
  jethTarget: string,
  jethCaller: string,
  solTarget: string,
  solCaller: string,
  tName: string,
  cName: string,
  sigs: string[],
) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const tj = await hj.deploy(compile(jethTarget, { fileName: 'T.jeth' }).creationBytecode);
  const ts = await hs.deploy(compileSolidity(SPDX + solTarget, tName).creation);
  const cj = await hj.deploy(compile(jethCaller, { fileName: 'C.jeth' }).creationBytecode);
  const cs = await hs.deploy(compileSolidity(SPDX + solCaller, cName).creation);
  for (const sig of sigs) {
    const rj = await hj.call(cj, '0x' + sel(sig) + P(BigInt(tj.toString())));
    const rs = await hs.call(cs, '0x' + sel(sig) + P(BigInt(ts.toString())));
    expect(rj.success, `${sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${sig}: returndata`).toBe(rs.returnHex);
  }
}

describe('decode field inside call/staticcall options', () => {
  it('produces byte-identical bytecode to the chained .decode form (value/dynamic/array/tuple)', () => {
    // For each shape, an in-object decode and a chained .decode caller that are otherwise identical must
    // compile to the SAME creation bytecode (they lower to the same abiDecode-over-extCall IR).
    const single = (decExpr: string, chain: string, ret: string) => ({
      inObj: `@contract class C { @external @view f(t: address): ${ret} { return t.staticcall({ data: abi.encodeWithSignature("g()"), success: { condition: this.ok, revert: "f" }, decode: ${decExpr} }); } }`,
      chain: `@contract class C { @external @view f(t: address): ${ret} { return t.staticcall({ data: abi.encodeWithSignature("g()"), success: { condition: this.ok, revert: "f" } }).decode(${chain}); } }`,
    });
    const cases = [
      single('u256', 'u256', 'u256'),
      single('address', 'address', 'address'),
      single('bool', 'bool', 'bool'),
      single('bytes4', 'bytes4', 'bytes4'),
      single('string', 'string', 'string'),
      single('bytes', 'bytes', 'bytes'),
    ];
    for (const c of cases) {
      const a = compile(c.inObj, { fileName: 'C.jeth' }).creationBytecode;
      const b = compile(c.chain, { fileName: 'C.jeth' }).creationBytecode;
      expect(a).toBe(b);
    }
    // dynamic array + fixed array (re-encode the decoded value so the return shape is identical both ways)
    const arrInObj = `class C { get f(t: address): External<bytes> { let xs: u256[] = t.staticcall({ data: abi.encodeWithSignature("g()"), success: { condition: this.ok, revert: "f" }, decode: u256[] }); return abi.encode(xs); } }`;
    const arrChain = `class C { get f(t: address): External<bytes> { let xs: u256[] = t.staticcall({ data: abi.encodeWithSignature("g()"), success: { condition: this.ok, revert: "f" } }).decode(u256[]); return abi.encode(xs); } }`;
    expect(compile(arrInObj, { fileName: 'C.jeth' }).creationBytecode).toBe(
      compile(arrChain, { fileName: 'C.jeth' }).creationBytecode,
    );
    // tuple destructuring
    const tupInObj = `class C { get f(t: address): External<bytes> { let [a, s]: [u256, string] = t.staticcall({ data: abi.encodeWithSignature("g()"), success: { condition: this.ok, revert: "f" }, decode: [u256, string] }); return abi.encode(a, s); } }`;
    const tupChain = `class C { get f(t: address): External<bytes> { let [a, s]: [u256, string] = t.staticcall({ data: abi.encodeWithSignature("g()"), success: { condition: this.ok, revert: "f" } }).decode([u256, string]); return abi.encode(a, s); } }`;
    expect(compile(tupInObj, { fileName: 'C.jeth' }).creationBytecode).toBe(
      compile(tupChain, { fileName: 'C.jeth' }).creationBytecode,
    );
  });

  it('single value/dynamic decode is byte-identical to solc cross-contract', async () => {
    const TJ = `class T {
      get u(): External<u256> { return 0xbeefn; }
      get s(): External<string> { return "decoded in call"; }
      get a(): External<address> { return 0x1234567890AbcdEF1234567890aBcdef12345678n; }
    }`;
    const TS = `contract T {
      function u() external pure returns (uint256){ return 0xbeef; }
      function s() external pure returns (string memory){ return "decoded in call"; }
      function a() external pure returns (address){ return 0x1234567890AbcdEF1234567890aBcdef12345678; }
    }`;
    const CJ = `class C {
      get cu(t: address): External<u256> { return t.staticcall({ data: abi.encodeWithSignature("u()"), success: { condition: this.ok, revert: "f" }, decode: u256 }); }
      get cs(t: address): External<string> { return t.staticcall({ data: abi.encodeWithSignature("s()"), success: { condition: this.ok, revert: "f" }, decode: string }); }
      get ca(t: address): External<address> { return t.staticcall({ data: abi.encodeWithSignature("a()"), success: { condition: this.ok, revert: "f" }, decode: address }); }
    }`;
    const CS = `contract C {
      function cu(address t) external view returns (uint256){ (bool ok, bytes memory r)=t.staticcall(abi.encodeWithSignature("u()")); require(ok,"f"); return abi.decode(r,(uint256)); }
      function cs(address t) external view returns (string memory){ (bool ok, bytes memory r)=t.staticcall(abi.encodeWithSignature("s()")); require(ok,"f"); return abi.decode(r,(string)); }
      function ca(address t) external view returns (address){ (bool ok, bytes memory r)=t.staticcall(abi.encodeWithSignature("a()")); require(ok,"f"); return abi.decode(r,(address)); }
    }`;
    await rtCross(TJ, CJ, TS, CS, 'T', 'C', ['cu(address)', 'cs(address)', 'ca(address)']);
  });

  it('tuple decode via destructuring is byte-identical to solc cross-contract', async () => {
    const TJ = `class T {
      get pair(): External<bytes> { return abi.encode(0x2an, "tuple!"); }
      get trip(): External<bytes> { return abi.encode(0x7bn, "three", true); }
    }`;
    const TS = `contract T {
      function pair() external pure returns (bytes memory){ return abi.encode(uint256(0x2a), "tuple!"); }
      function trip() external pure returns (bytes memory){ return abi.encode(uint256(0x7b), "three", true); }
    }`;
    // the target returns abi.encode(...) as bytes, so the caller decodes the INNER payload: it first decodes
    // the outer bytes wrapper, then the tuple. Mirror exactly on both sides.
    const CJ = `class C {
      get cp(t: address): External<bytes> {
        let raw: bytes = t.staticcall({ data: abi.encodeWithSignature("pair()"), success: { condition: this.ok, revert: "f" }, decode: bytes });
        let [n, s]: [u256, string] = abi.decode(raw, [u256, string]);
        return abi.encode(n, s);
      }
      get ct(t: address): External<bytes> {
        let [n, s, b]: [u256, string, bool] = t.staticcall({ data: abi.encodeWithSignature("trip()"), success: { condition: this.ok, revert: "f" }, decode: bytes }).decode([u256, string, bool]);
        return abi.encode(n, s, b);
      }
    }`;
    const CS = `contract C {
      function cp(address t) external view returns (bytes memory){
        (bool ok, bytes memory r)=t.staticcall(abi.encodeWithSignature("pair()")); require(ok,"f");
        bytes memory raw = abi.decode(r,(bytes));
        (uint256 n, string memory s)=abi.decode(raw,(uint256,string)); return abi.encode(n,s);
      }
      function ct(address t) external view returns (bytes memory){
        (bool ok, bytes memory r)=t.staticcall(abi.encodeWithSignature("trip()")); require(ok,"f");
        bytes memory raw = abi.decode(r,(bytes));
        (uint256 n, string memory s, bool b)=abi.decode(raw,(uint256,string,bool)); return abi.encode(n,s,b);
      }
    }`;
    await rtCross(TJ, CJ, TS, CS, 'T', 'C', ['cp(address)', 'ct(address)']);
  });

  it('a direct in-object tuple destructure is byte-identical to solc (resolveCallDecodeTuple path)', async () => {
    // The target returns a CLEAN ABI tuple (its returndata IS abi.encode of the components), so
    // `let [a, b] = addr.staticcall({..., decode: [T1, T2]})` decodes the returndata directly. JETH cannot
    // return a multi-value tuple from a method, so the target is solc on BOTH harnesses; only the CALLER
    // (the unit under test) differs (JETH in-object decode vs the solc abi.decode equivalent).
    const TS = `contract T {
      function pa() external pure returns (uint256, address){ return (0x2a, 0xfEdcBA9876543210FedCBa9876543210fEdCBa98); }
      function ps() external pure returns (uint256, string memory){ return (0x7b, "direct tuple"); }
    }`;
    const CJ = `class C {
      get cpa(t: address): External<bytes> { let [n, a]: [u256, address] = t.staticcall({ data: abi.encodeWithSignature("pa()"), success: { condition: this.ok, revert: "f" }, decode: [u256, address] }); return abi.encode(n, a); }
      get cps(t: address): External<bytes> { let [n, s]: [u256, string] = t.staticcall({ data: abi.encodeWithSignature("ps()"), success: { condition: this.ok, revert: "f" }, decode: [u256, string] }); return abi.encode(n, s); }
    }`;
    const CS = `contract C {
      function cpa(address t) external view returns (bytes memory){ (bool ok, bytes memory r)=t.staticcall(abi.encodeWithSignature("pa()")); require(ok,"f"); (uint256 n, address a)=abi.decode(r,(uint256,address)); return abi.encode(n,a); }
      function cps(address t) external view returns (bytes memory){ (bool ok, bytes memory r)=t.staticcall(abi.encodeWithSignature("ps()")); require(ok,"f"); (uint256 n, string memory s)=abi.decode(r,(uint256,string)); return abi.encode(n,s); }
    }`;
    const hj = await Harness.create();
    const hs = await Harness.create();
    const tj = await hj.deploy(compileSolidity(SPDX + TS, 'T').creation); // solc target on both harnesses
    const ts = await hs.deploy(compileSolidity(SPDX + TS, 'T').creation);
    const cj = await hj.deploy(compile(CJ, { fileName: 'C.jeth' }).creationBytecode);
    const cs = await hs.deploy(compileSolidity(SPDX + CS, 'C').creation);
    for (const sig of ['cpa(address)', 'cps(address)']) {
      const rj = await hj.call(cj, '0x' + sel(sig) + P(BigInt(tj.toString())));
      const rs = await hs.call(cs, '0x' + sel(sig) + P(BigInt(ts.toString())));
      expect(rj.success, `${sig}: success`).toBe(rs.success);
      expect(rj.returnHex, `${sig}: returndata`).toBe(rs.returnHex);
    }
  });

  it('a failing success condition reverts before decode (byte-identical to solc)', async () => {
    const TJ = `class T { get ok(): External<u256> { return 5n; } get boom(): External<u256> { revertWith(abi.encode()); return 0n; } }`;
    const TS = `contract T { function ok() external pure returns (uint256){ return 5; } function boom() external pure returns (uint256){ revert(); } }`;
    const CJ = `class C {
      get good(t: address): External<u256> { return t.staticcall({ data: abi.encodeWithSignature("ok()"), success: { condition: this.ok, revert: "FAILED" }, decode: u256 }); }
      get bad(t: address): External<u256> { return t.staticcall({ data: abi.encodeWithSignature("boom()"), success: { condition: this.ok, revert: "FAILED" }, decode: u256 }); }
    }`;
    const CS = `contract C {
      function good(address t) external view returns (uint256){ (bool ok, bytes memory r)=t.staticcall(abi.encodeWithSignature("ok()")); require(ok,"FAILED"); return abi.decode(r,(uint256)); }
      function bad(address t) external view returns (uint256){ (bool ok, bytes memory r)=t.staticcall(abi.encodeWithSignature("boom()")); require(ok,"FAILED"); return abi.decode(r,(uint256)); }
    }`;
    await rtCross(TJ, CJ, TS, CS, 'T', 'C', ['good(address)', 'bad(address)']);
  });

  it('accepts the supported decode-in-call shapes', () => {
    const ok = (body: string) => `@contract class C { @external f(t: address): ${body} }`;
    expect(
      jethAccepts(
        ok(
          'u256 { return t.call({ data: abi.encode(), value: 1n, success: { condition: this.ok, revert: "x" }, decode: u256 }); }',
        ),
      ),
    ).toBe(true);
    expect(
      jethAccepts(
        ok(
          'string { return t.staticcall({ data: abi.encode(), success: { condition: this.ok, revert: "x" }, decode: string }); }',
        ),
      ),
    ).toBe(true);
    expect(
      jethAccepts(
        ok(
          'bytes { let xs: u256[] = t.staticcall({ data: abi.encode(), success: { condition: this.ok, revert: "x" }, decode: u256[] }); return abi.encode(xs); }',
        ),
      ),
    ).toBe(true);
    expect(
      jethAccepts(
        ok(
          'bytes { let xs: Arr<u256,3> = t.staticcall({ data: abi.encode(), success: { condition: this.ok, revert: "x" }, decode: Arr<u256,3> }); return abi.encode(xs); }',
        ),
      ),
    ).toBe(true);
    expect(
      jethAccepts(
        ok(
          'bytes { let [a, b]: [u256, address] = t.staticcall({ data: abi.encode(), success: { condition: this.ok, revert: "x" }, decode: [u256, address] }); return abi.encode(a, b); }',
        ),
      ),
    ).toBe(true);
  });

  it('cleanly rejects (no crash) decode misuse with a precise diagnostic', () => {
    const f = (body: string) => `@contract class C { @external f(t: address): ${body} }`;
    // decode on the raw escape hatch -> JETH303
    expect(
      jethError(f('bytes { let [ok, r]: [bool, bytes] = t.tryCall({ data: abi.encode(), decode: u256 }); return r; }')),
    ).toContain('JETH303');
    // unknown type name -> JETH321
    expect(
      jethError(
        f(
          'u256 { return t.staticcall({ data: abi.encode(), success: { condition: this.ok, revert: "x" }, decode: NotAType }); }',
        ),
      ),
    ).toContain('JETH321');
    // empty tuple -> JETH321
    expect(
      jethError(
        f(
          'u256 { return t.staticcall({ data: abi.encode(), success: { condition: this.ok, revert: "x" }, decode: [] }); }',
        ),
      ),
    ).toContain('JETH321');
    // a struct target is now SUPPORTED for decode (decode: P reuses the same abiDecode codec - the memory
    // decoder builds the pointer-headed struct image; byte-identical, see arch-abi-decode-aggregate.test.ts)
    expect(
      jethError(
        `type P = { a: u256; s: string; }; class C { get f(t: address): External<u256> { let p: P = t.staticcall({ data: abi.encode(), success: { condition: this.ok, revert: "x" }, decode: P }); return p.a; } }`,
      ),
    ).toEqual([]);
    // Residual C lifted string[] (and P[] / bytes[] / u256[][]) as decode targets and Residual B memory-array
    // locals, so `decode: string[]` bound to a `let xs: string[]` is now ACCEPTED (byte-identical decode is
    // verified in arch-residual-c-decode-array.test.ts; the low-level-call decode reuses the same abiDecode IR).
    expect(
      jethAccepts(
        f(
          'bytes { let xs: string[] = t.staticcall({ data: abi.encode(), success: { condition: this.ok, revert: "x" }, decode: string[] }); return abi.encode(xs); }',
        ),
      ),
    ).toBe(true);
    // tuple decode bound to a single name -> JETH323
    expect(
      jethError(
        f(
          'bytes { let x: bytes = t.staticcall({ data: abi.encode(), success: { condition: this.ok, revert: "x" }, decode: [u256, address] }); return x; }',
        ),
      ),
    ).toContain('JETH323');
    // single decode destructured -> JETH323
    expect(
      jethError(
        `class C { get f(t: address): External<u256> { let [a, b]: [u256, u256] = t.staticcall({ data: abi.encode(), success: { condition: this.ok, revert: "x" }, decode: u256 }); return a; } }`,
      ),
    ).toContain('JETH323');
    // none of these crashed the compiler (JETH900)
    for (const src of [
      f('bytes { let [ok, r]: [bool, bytes] = t.tryCall({ data: abi.encode(), decode: u256 }); return r; }'),
      f(
        'u256 { return t.staticcall({ data: abi.encode(), success: { condition: this.ok, revert: "x" }, decode: NotAType }); }',
      ),
    ])
      expect(jethError(src)).not.toContain('JETH900');
  });
});
