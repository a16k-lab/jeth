// Backend: hand the generated Yul to solc (Yul mode) and parse out bytecode
// (directive §3.2, §3.3). solc runs its optimizer, stack scheduler, assembler and
// JUMPDEST resolution -- the three parts toy EVM compilers die on.
import solc from 'solc';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { join } from 'node:path';

/** solc link-reference map: file -> library name -> the byte positions of the 34-hex `__$..$__`
 *  placeholder (length 20) that a deployer substitutes with the linked library's address. In Yul
 *  mode (a `linkersymbol("L")`) the file key is "" and the library name is the symbol. */
export type LinkReferences = Record<string, Record<string, { start: number; length: number }[]>>;

export interface SolcResult {
  creationBytecode: string; // hex without 0x
  runtimeBytecode: string; // hex without 0x
  yul: string;
  // Phase B: present only when the Yul referenced a `linkersymbol(...)` (an external library
  // delegatecall). Empty objects otherwise.
  creationLinkReferences: LinkReferences;
  runtimeLinkReferences: LinkReferences;
}

interface SolcError {
  severity: 'error' | 'warning' | 'info';
  formattedMessage?: string;
  message: string;
  type: string;
}

export class SolcError2 extends Error {}

// ---- Yul-backend cache (opt-in, side-effect-free) ---------------------------
// solc assembling the emitted Yul into bytecode is ~92% of a JETH compile (profiled). That step is a
// PURE function of (yul, contractName, evmVersion) plus the fixed optimizer settings and the exact
// solc version, so memoizing it is transparent: the key is the FULL Yul (a change of one character
// is a new key), a miss always reassembles, only SUCCESSES are cached, and any cache read/write
// error falls back to a fresh assembly. Critically for the dev loop: when the JETH front-end changes
// the Yul it emits for a contract, that contract reassembles (new Yul -> new key); every contract
// whose Yul is unchanged hits the cache - so it can NEVER return stale/wrong bytecode. It is OPT-IN
// via the JETH_COMPILE_CACHE env var (read at CALL time so a test setup can enable it): the
// production `jethc` CLI never sets it, so normal compiles are uncached and write nothing to disk.
const YUL_CACHE_VERSION = '1';
const YUL_CACHE_DIR = join(process.cwd(), 'node_modules', '.cache', 'jeth-yul');
const yulMemCache = new Map<string, SolcResult>();
let yulCacheDirReady = false;

function yulCacheKey(yul: string, contractName: string, evmVersion: string): string {
  return createHash('sha256')
    .update(YUL_CACHE_VERSION)
    .update('\x00')
    .update(solc.version())
    .update('\x00')
    .update(evmVersion)
    .update('\x00')
    .update(contractName)
    .update('\x00')
    .update(yul)
    .digest('hex');
}

function readYulCache(key: string): SolcResult | undefined {
  try {
    const f = join(YUL_CACHE_DIR, key + '.json');
    if (!existsSync(f)) return undefined;
    return JSON.parse(readFileSync(f, 'utf8')) as SolcResult;
  } catch {
    return undefined; // corrupt / torn read -> reassemble
  }
}

function writeYulCache(key: string, res: SolcResult): void {
  try {
    if (!yulCacheDirReady) {
      mkdirSync(YUL_CACHE_DIR, { recursive: true });
      yulCacheDirReady = true;
    }
    const tmp = join(YUL_CACHE_DIR, `${key}.${process.pid}.tmp`);
    writeFileSync(tmp, JSON.stringify(res));
    renameSync(tmp, join(YUL_CACHE_DIR, key + '.json'));
  } catch {
    /* best-effort; a failure leaves correctness untouched (reassembles next time) */
  }
}

export function compileYul(yul: string, contractName: string, evmVersion = 'cancun'): SolcResult {
  if (!process.env.JETH_COMPILE_CACHE) return compileYulUncached(yul, contractName, evmVersion);
  const key = yulCacheKey(yul, contractName, evmVersion);
  const mem = yulMemCache.get(key);
  if (mem) return mem;
  const disk = readYulCache(key);
  if (disk) {
    yulMemCache.set(key, disk);
    return disk;
  }
  const res = compileYulUncached(yul, contractName, evmVersion); // throws on solc error (not cached)
  yulMemCache.set(key, res);
  writeYulCache(key, res);
  return res;
}

function compileYulUncached(yul: string, contractName: string, evmVersion = 'cancun'): SolcResult {
  const input = {
    language: 'Yul',
    sources: { [`${contractName}.yul`]: { content: yul } },
    settings: {
      optimizer: { enabled: true, runs: 200, details: { yul: true } },
      evmVersion,
      outputSelection: {
        '*': {
          '*': [
            'evm.bytecode.object',
            'evm.bytecode.linkReferences',
            'evm.deployedBytecode.object',
            'evm.deployedBytecode.linkReferences',
          ],
        },
      },
    },
  };

  const output = JSON.parse(solc.compile(JSON.stringify(input)));

  const errors: SolcError[] = output.errors ?? [];
  const fatal = errors.filter((e) => e.severity === 'error');
  if (fatal.length > 0) {
    const msg = fatal.map((e) => e.formattedMessage ?? e.message).join('\n');
    throw new SolcError2(`solc failed to compile generated Yul:\n${msg}\n\n--- generated Yul ---\n${yul}`);
  }

  const fileOut = output.contracts?.[`${contractName}.yul`];
  if (!fileOut) throw new SolcError2(`solc produced no output for ${contractName}.yul`);
  // The Yul object name is the top-level object; pick the first contract entry.
  const contract = fileOut[contractName] ?? Object.values(fileOut)[0];
  if (!contract) throw new SolcError2(`solc produced no contract for ${contractName}`);

  return {
    creationBytecode: contract.evm.bytecode.object,
    runtimeBytecode: contract.evm.deployedBytecode.object,
    yul,
    creationLinkReferences: (contract.evm.bytecode.linkReferences ?? {}) as LinkReferences,
    runtimeLinkReferences: (contract.evm.deployedBytecode.linkReferences ?? {}) as LinkReferences,
  };
}

export function solcVersion(): string {
  return solc.version();
}
