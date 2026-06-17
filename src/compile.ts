// Top-level pipeline orchestrator (directive §5): source -> tokens/AST -> subset
// validation -> semantic analysis + type check -> storage layout -> Yul -> solc
// -> bytecode + ABI.
import { parse } from './parser.js';
import { DiagnosticBag, CompileError, Diagnostic } from './diagnostics.js';
import { validateSubset } from './validator.js';
import { analyze } from './analyzer.js';
import { emitYul, UnsupportedError } from './yul.js';
import { compileYul } from './solc.js';
import { emitAbi, AbiItem } from './abi.js';
import type { ContractIR } from './ir.js';
import { displayName } from './types.js';

export interface StorageLayoutEntry {
  name: string;
  type: string;
  slot: number;
  offset: number;
}

export interface CompileResult {
  contractName: string;
  abi: AbiItem[];
  creationBytecode: string; // hex, no 0x
  runtimeBytecode: string; // hex, no 0x
  yul: string;
  storageLayout: StorageLayoutEntry[];
  ir: ContractIR;
  diagnostics: Diagnostic[];
}

export interface CompileOptions {
  fileName?: string;
  evmVersion?: string;
}

export function compile(source: string, opts: CompileOptions = {}): CompileResult {
  const fileName = opts.fileName ?? 'contract.jeth';
  const parsed = parse(source, fileName);
  const diags = new DiagnosticBag(parsed.sourceFile, fileName);

  // Phase 0: subset validation (collects, does not throw yet).
  validateSubset(parsed.sourceFile, diags);

  // Phase 1: semantic analysis + type checking.
  const ir = analyze(parsed.sourceFile, diags);

  // Surface all front-end diagnostics together.
  diags.throwIfErrors();
  if (!ir) throw new CompileError(diags.items);

  // Lowering -> Yul.
  let yul: string;
  try {
    yul = emitYul(ir);
  } catch (e) {
    if (e instanceof UnsupportedError) {
      throw new CompileError([
        {
          severity: 'error',
          code: 'JETH900',
          message: e.message,
          file: fileName,
          line: 1,
          column: 1,
          length: 1,
        },
      ]);
    }
    throw e;
  }

  // Backend -> bytecode. A failure here means codegen emitted invalid Yul (an
  // internal compiler bug); surface it as a clean diagnostic, not a raw crash.
  let out;
  try {
    out = compileYul(yul, ir.name, opts.evmVersion);
  } catch (e) {
    throw new CompileError([
      {
        severity: 'error',
        code: 'JETH901',
        message: `internal compiler error: the backend rejected generated Yul: ${
          e instanceof Error ? e.message : String(e)
        }`,
        file: fileName,
        line: 1,
        column: 1,
        length: 1,
      },
    ]);
  }

  const storageLayout: StorageLayoutEntry[] = ir.stateVars.map((v) => ({
    name: v.name,
    type: displayName(v.type),
    slot: v.slot,
    offset: v.offset,
  }));

  return {
    contractName: ir.name,
    abi: emitAbi(ir),
    creationBytecode: out.creationBytecode,
    runtimeBytecode: out.runtimeBytecode,
    yul,
    storageLayout,
    ir,
    diagnostics: diags.items,
  };
}
