// @constant address (Phase 6): a slot-free compile-time address constant, substituted at each read
// site, byte-identical to solc and consuming no storage slot.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n).slice(2);

async function diff(jeth: string, sol: string, calls: { sig: string; args?: string }[], slots: bigint[] = []) {
  const jb = compile(jeth, { fileName: 'C.jeth' });
  const sb = compileSolidity(SPDX + sol, 'C');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(jb.creationBytecode);
  const as = await hs.deploy(sb.creation);
  for (const c of calls) {
    const data = '0x' + sel(c.sig) + (c.args ?? '');
    const rj = await hj.call(aj, data);
    const rs = await hs.call(as, data);
    expect(rj.success, `${c.sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${c.sig}: returndata`).toBe(rs.returnHex);
  }
  for (const s of slots) expect(await readSlot(hj, aj, s), `slot ${s}`).toBe(await readSlot(hs, as, s));
}

describe('@constant address vs Solidity', () => {
  it('read, compare, and consume no storage slot', async () => {
    await diff(
      `@contract class C { @constant K: address = address(0x1111111111111111111111111111111111111111n); @state x: u256 = 7n; @external @view getK(): address { return this.K; } @external @view isK(a: address): bool { return a == this.K; } @external @view getX(): u256 { return this.x; } }`,
      `contract C { address constant K = 0x1111111111111111111111111111111111111111; uint256 x = 7; function getK() external view returns (address){ return K; } function isK(address a) external view returns (bool){ return a == K; } function getX() external view returns (uint256){ return x; } }`,
      [
        { sig: 'getK()' },
        { sig: 'isK(address)', args: W(0x1111111111111111111111111111111111111111n) },
        { sig: 'isK(address)', args: W(0x2222n) },
        { sig: 'getX()' },
      ],
      [0n], // x is at slot 0 (the constant consumes no slot)
    );
  });

  it('address(0) constant', async () => {
    await diff(
      `@contract class C { @constant Z: address = address(0n); @external @view f(): address { return this.Z; } }`,
      `contract C { address constant Z = address(0); function f() external view returns (address){ return Z; } }`,
      [{ sig: 'f()' }],
    );
  });
});
