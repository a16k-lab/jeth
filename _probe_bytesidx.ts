import { compile } from './src/compile.js';
import { compileSolidity } from './test/_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

// ---- JETH: the claimed write form ----
const jethWrite = `@contract class C { @state m: mapping<u256, bytes>; @external setAt(k: u256, i: u256, x: bytes1): void { this.m[k][i] = x; } }`;
// ---- JETH: the read form the claim says already compiles ----
const jethRead = `@contract class C { @state m: mapping<u256, bytes>; @external getAt(k: u256, i: u256): bytes1 { return this.m[k][i]; } }`;

function tryJeth(label: string, src: string) {
  try {
    compile(src, { fileName: 'C.jeth' });
    console.log(`JETH ${label}: ACCEPT`);
  } catch (e: any) {
    const diags = e?.diagnostics ?? [];
    console.log(`JETH ${label}: REJECT`, JSON.stringify(diags.map((d: any) => `${d.code}: ${d.message}`)));
  }
}

tryJeth('write (this.m[k][i]=x)', jethWrite);
tryJeth('read  (return this.m[k][i])', jethRead);

// ---- solc: semantically identical ----
// mapping(uint256 => bytes) m; setAt writes one byte. Solidity allows m[k][i] = x where x is bytes1.
const solWrite = SPDX + `contract C {
  mapping(uint256 => bytes) m;
  function setAt(uint256 k, uint256 i, bytes1 x) external { m[k][i] = x; }
}`;
const solRead = SPDX + `contract C {
  mapping(uint256 => bytes) m;
  function getAt(uint256 k, uint256 i) external view returns (bytes1) { return m[k][i]; }
}`;

function trySol(label: string, src: string) {
  try {
    compileSolidity(src, 'C');
    console.log(`SOLC ${label}: ACCEPT`);
  } catch (e: any) {
    console.log(`SOLC ${label}: REJECT`, (e?.message ?? String(e)).split('\n').slice(0, 4).join(' | '));
  }
}

trySol('write (m[k][i]=x)', solWrite);
trySol('read  (return m[k][i])', solRead);
