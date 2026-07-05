// Top-level pipeline orchestrator (directive §5): source -> tokens/AST -> subset
// validation -> semantic analysis + type check -> storage layout -> Yul -> solc
// -> bytecode + ABI.
import { parse } from './parser.js';
import { expandDiamond } from './diamond.js';
import { DiagnosticBag, CompileError, Diagnostic } from './diagnostics.js';
import { validateSubset } from './validator.js';
import { analyze } from './analyzer.js';
import { emitYul, emitLibraryYul, UnsupportedError } from './yul.js';
import { compileYul, LinkReferences } from './solc.js';
import { emitAbi, AbiItem } from './abi.js';
import type { ContractIR } from './ir.js';
import { displayName } from './types.js';

export interface StorageLayoutEntry {
  name: string;
  type: string;
  slot: number;
  offset: number;
}

/** Phase B: a compiled external (delegatecall) library object, deployed separately and linked into
 *  the contract at deploy time. `creationBytecode` deploys it; its address is substituted at every
 *  `linkReferences` position of the contract's creation/runtime bytecode. */
export interface CompiledLibrary {
  name: string;
  creationBytecode: string; // hex, no 0x
  runtimeBytecode: string; // hex, no 0x
  // Positions inside THIS library's OWN creation bytecode where ANOTHER external library's address must
  // be linked (an @external library that calls another @external library carries the callee's placeholder
  // in its bytecode). Empty/absent when the library references no other library. Consumed by deployLinked
  // to link + deploy libraries bottom-up (a callee library is deployed and substituted before its caller).
  linkReferences?: LinkReferences;
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
  // Phase B: present ONLY when the contract references an external (delegatecall) library. `libraries`
  // are the separately-deployed library objects; `linkReferences` are the contract's creation-bytecode
  // placeholder positions (library name -> positions) to substitute with each library's deployed
  // address. Absent (undefined) for an ordinary single-contract compile (backward compatible).
  libraries?: CompiledLibrary[];
  linkReferences?: LinkReferences;
}

export interface CompileOptions {
  fileName?: string;
  evmVersion?: string;
}

export function compile(source: string, opts: CompileOptions = {}): CompileResult {
  const fileName = opts.fileName ?? 'contract.jeth';

  // Phase 3 (DIAMOND): expand a `@diamond('array')` class into the synthesized `@contract` BEFORE parse
  // (a source-text transform, like the parser's enum hoist). Gate diagnostics (positions in the ORIGINAL
  // source) are surfaced first; on a gate error we throw without parsing the (now invalid) expansion.
  const dia = expandDiamond(source, fileName);
  if (dia.diagnostics.length > 0) {
    throw new CompileError(
      dia.diagnostics.map((d) => ({
        severity: 'error' as const,
        code: d.code,
        message: d.message,
        file: fileName,
        line: d.line,
        column: d.column,
        length: d.length,
      })),
    );
  }
  const effectiveSource = dia.expanded ? dia.source : source;

  const parsed = parse(effectiveSource, fileName);
  const diags = new DiagnosticBag(parsed.sourceFile, fileName);

  // Phase 0: subset validation (collects, does not throw yet).
  validateSubset(parsed.sourceFile, diags);

  // Phase 1: semantic analysis + type checking.
  const ir = analyze(
    parsed.sourceFile,
    diags,
    dia.expanded && dia.name ? { name: dia.name, variant: dia.variant ?? 'array' } : undefined,
  );

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
          code: e.code,
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

  // stateVars only ever holds @state vars, which the planner lays out at small sequential slots
  // (@storage('ns') namespaced fields are NOT in stateVars - they live at their keccak base and are
  // never exported here), so narrowing to number for the debug layout table is exact and lossless.
  const storageLayout: StorageLayoutEntry[] = ir.stateVars.map((v) => ({
    name: v.name,
    type: displayName(v.type),
    slot: Number(v.slot),
    offset: v.offset,
  }));

  // Phase B: compile each referenced external (delegatecall) library to its own bytecode. The contract
  // carries a `linkersymbol(...)` placeholder per library; solc returns its positions in linkReferences.
  let libraries: CompiledLibrary[] | undefined;
  let linkReferences: LinkReferences | undefined;
  if (ir.libraries && ir.libraries.length > 0) {
    libraries = ir.libraries.map((lib) => {
      let libYul: string;
      try {
        libYul = emitLibraryYul(lib);
      } catch (e) {
        // Surface a lowering rejection inside a library body as the same clean diagnostic the
        // contract path produces (previously an UnsupportedError here escaped as a raw throw).
        if (e instanceof UnsupportedError) {
          throw new CompileError([
            { severity: 'error', code: e.code, message: e.message, file: fileName, line: 1, column: 1, length: 1 },
          ]);
        }
        throw e;
      }
      let libOut;
      try {
        libOut = compileYul(libYul, lib.name, opts.evmVersion);
      } catch (e) {
        throw new CompileError([
          {
            severity: 'error',
            code: 'JETH901',
            message: `internal compiler error: the backend rejected generated library Yul for '${lib.name}': ${
              e instanceof Error ? e.message : String(e)
            }`,
            file: fileName,
            line: 1,
            column: 1,
            length: 1,
          },
        ]);
      }
      // libOut.creationLinkReferences records where OTHER libraries' placeholders sit inside THIS
      // library's creation bytecode (present when an @external library calls another @external library).
      return {
        name: lib.name,
        creationBytecode: libOut.creationBytecode,
        runtimeBytecode: libOut.runtimeBytecode,
        linkReferences: libOut.creationLinkReferences,
      };
    });
    linkReferences = out.creationLinkReferences;
  }

  return {
    contractName: ir.name,
    abi: emitAbi(ir),
    creationBytecode: out.creationBytecode,
    runtimeBytecode: out.runtimeBytecode,
    yul,
    storageLayout,
    ir,
    diagnostics: diags.items,
    libraries,
    linkReferences,
  };
}
