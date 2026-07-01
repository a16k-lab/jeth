// Test-only helper: compile reference Solidity with the same solc-js the compiler
// uses, for differential testing (directive §7).
import solc from 'solc';
import { setLengthLeft, hexToBytes, bytesToHex, type Address } from '@ethereumjs/util';
import type { Harness } from '../src/evm.js';

export interface SolBuild {
  creation: string; // hex, no 0x
  storageLayout: { label: string; slot: string; offset: number; type: string }[];
}

export function compileSolidity(source: string, contractName: string): SolBuild {
  const input = {
    language: 'Solidity',
    sources: { 'C.sol': { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: 'cancun',
      outputSelection: { '*': { '*': ['evm.bytecode.object', 'storageLayout'] } },
    },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  const fatal = (out.errors ?? []).filter((e: any) => e.severity === 'error');
  if (fatal.length) throw new Error('solc(Solidity) failed:\n' + fatal.map((e: any) => e.formattedMessage).join('\n'));
  const c = out.contracts['C.sol'][contractName];
  return {
    creation: c.evm.bytecode.object,
    storageLayout: (c.storageLayout?.storage ?? []).map((s: any) => ({
      label: s.label,
      slot: s.slot,
      offset: s.offset,
      type: s.type,
    })),
  };
}

/** Read a raw 32-byte storage slot as a 0x-prefixed hex string. */
export async function readSlot(h: Harness, addr: Address, slot: bigint): Promise<string> {
  const key = setLengthLeft(hexToBytes(('0x' + slot.toString(16)) as `0x${string}`), 32);
  const v = await h.evm.stateManager.getStorage(addr, key);
  return bytesToHex(setLengthLeft(v, 32));
}

// ---- Phase B: external (delegatecall) library linking ----------------------

export type SolLinkReferences = Record<string, Record<string, { start: number; length: number }[]>>;

export interface SolLinkedBuild {
  contractCreation: string; // hex, no 0x (carries `__$..$__` placeholders)
  // each library's deployable creation bytecode + its OWN link references (a library that calls another
  // library carries the callee's placeholder, so it must be linked before it can deploy).
  libraries: { name: string; creation: string; linkReferences: SolLinkReferences }[];
  linkReferences: SolLinkReferences; // the contract's creation-bytecode placeholder positions
}

/** Compile a Solidity source that has external `library L { ... public ... }` declarations plus a
 *  `contract C`. Returns the contract's creation bytecode (with `__$..$__` placeholders), each named
 *  library's creation bytecode, and the contract's linkReferences (positions to substitute). The solc
 *  mirror for the JETH external-library tests. */
export function compileSolidityLinked(source: string, contractName: string, libNames: string[]): SolLinkedBuild {
  const input = {
    language: 'Solidity',
    sources: { 'C.sol': { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: 'cancun',
      outputSelection: {
        '*': { '*': ['evm.bytecode.object', 'evm.bytecode.linkReferences'] },
      },
    },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  const fatal = (out.errors ?? []).filter((e: any) => e.severity === 'error');
  if (fatal.length) throw new Error('solc(Solidity) failed:\n' + fatal.map((e: any) => e.formattedMessage).join('\n'));
  const c = out.contracts['C.sol'][contractName];
  const libraries = libNames.map((name) => {
    const lb = out.contracts['C.sol'][name].evm.bytecode;
    return { name, creation: lb.object, linkReferences: (lb.linkReferences ?? {}) as SolLinkReferences };
  });
  return {
    contractCreation: c.evm.bytecode.object,
    libraries,
    linkReferences: (c.evm.bytecode.linkReferences ?? {}) as SolLinkReferences,
  };
}

/** Deploy a solc external-library-linked build (deploy each library, substitute its 20-byte address at
 *  every linkReference position of the contract creation bytecode, deploy the contract). Returns the
 *  contract address. */
export async function deploySolLinked(h: Harness, build: SolLinkedBuild): Promise<Address> {
  const deployed = new Map<string, Address>();
  const link = (hex0: string, refs: SolLinkReferences): string => {
    let hex = hex0.startsWith('0x') ? hex0.slice(2) : hex0;
    for (const byLib of Object.values(refs)) {
      for (const [libName, positions] of Object.entries(byLib)) {
        const addr = deployed.get(libName);
        if (!addr) throw new Error(`deploySolLinked: no deployed library for '${libName}'`);
        const addrHex = addr.toString().slice(2).padStart(40, '0');
        for (const { start } of positions) {
          const cstart = start * 2;
          hex = hex.slice(0, cstart) + addrHex + hex.slice(cstart + 40);
        }
      }
    }
    return hex;
  };
  const depsOf = (refs: SolLinkReferences): string[] => {
    const s = new Set<string>();
    for (const byLib of Object.values(refs)) for (const n of Object.keys(byLib)) s.add(n);
    return [...s];
  };
  // Deploy libraries bottom-up: a library that calls another library carries the callee's placeholder,
  // so link + deploy the callee first, then the caller (mirrors Harness.deployLinked).
  const pending = [...build.libraries];
  while (pending.length) {
    const before = pending.length;
    for (let i = 0; i < pending.length; i++) {
      const lib = pending[i]!;
      if (depsOf(lib.linkReferences).every((d) => deployed.has(d))) {
        deployed.set(lib.name, await h.deploy(link(lib.creation, lib.linkReferences)));
        pending.splice(i, 1);
        i--;
      }
    }
    if (pending.length === before)
      throw new Error(`deploySolLinked: unresolved library link dependency among [${pending.map((l) => l.name).join(', ')}]`);
  }
  return h.deploy(link(build.contractCreation, build.linkReferences));
}
