// Backend: hand the generated Yul to solc (Yul mode) and parse out bytecode
// (directive §3.2, §3.3). solc runs its optimizer, stack scheduler, assembler and
// JUMPDEST resolution -- the three parts toy EVM compilers die on.
import solc from 'solc';

export interface SolcResult {
  creationBytecode: string; // hex without 0x
  runtimeBytecode: string; // hex without 0x
  yul: string;
}

interface SolcError {
  severity: 'error' | 'warning' | 'info';
  formattedMessage?: string;
  message: string;
  type: string;
}

export class SolcError2 extends Error {}

export function compileYul(yul: string, contractName: string, evmVersion = 'cancun'): SolcResult {
  const input = {
    language: 'Yul',
    sources: { [`${contractName}.yul`]: { content: yul } },
    settings: {
      optimizer: { enabled: true, runs: 200, details: { yul: true } },
      evmVersion,
      outputSelection: {
        '*': { '*': ['evm.bytecode.object', 'evm.deployedBytecode.object'] },
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
  };
}

export function solcVersion(): string {
  return solc.version();
}
