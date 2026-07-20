#!/usr/bin/env node

import { existsSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';
import { compile } from './compile.js';
import type { CompileResult } from './compile.js';
import { CompileError, formatDiagnostic } from './diagnostics.js';
import type { Diagnostic } from './diagnostics.js';
import { SolcError2, solcVersion } from './solc.js';

const EXIT_SUCCESS = 0;
const EXIT_COMPILE_ERROR = 1;
const EXIT_USAGE_ERROR = 2;
const EXIT_INTERNAL_ERROR = 3;
const DEFAULT_EVM_VERSION = 'cancun';
const STANDARD_JSON_SCHEMA = 1;
const EMIT_KINDS = ['abi', 'bin', 'yul', 'layout', 'metadata'] as const;

type EmitKind = (typeof EMIT_KINDS)[number];
type ErrorKind = 'usage' | 'input' | 'compile' | 'internal';

export interface CliIO {
  cwd: string;
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  readStdin: () => string;
}

interface CliOptions {
  input?: string;
  configPath?: string;
  outDir?: string;
  contract?: string;
  evmVersion?: string;
  emit?: Set<EmitKind>;
  printYul: boolean;
  printAbi: boolean;
  printBin: boolean;
  printLayout: boolean;
  json: boolean;
  standardJson: boolean;
  quiet: boolean;
  debug: boolean;
  help: boolean;
  version: boolean;
}

interface JethConfig {
  entry?: string;
  outDir?: string;
  contract?: string;
  evmVersion?: string;
  emit?: EmitKind[];
}

interface LoadedProject {
  entrySource: string;
  fileName: string;
  sources: Record<string, string>;
  sourceByFile: Record<string, string>;
  files: string[];
}

interface StandardJsonInput {
  language?: string;
  sources?: Record<string, { content?: string }>;
  settings?: {
    entry?: string;
    contract?: string;
    evmVersion?: string;
  };
}

class CliFailure extends Error {
  constructor(
    public readonly kind: ErrorKind,
    message: string,
    public readonly exitCode: number,
    public readonly diagnostics?: Diagnostic[],
    public readonly sourceByFile?: Record<string, string>,
  ) {
    super(message);
    this.name = 'CliFailure';
  }
}

function defaultIO(): CliIO {
  return {
    cwd: process.cwd(),
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    readStdin: () => readFileSync(0, 'utf8'),
  };
}

function line(text: string): string {
  return text.endsWith('\n') ? text : text + '\n';
}

function packageVersion(): string {
  let cursor = dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 5; depth++) {
    const candidate = resolve(cursor, 'package.json');
    if (existsSync(candidate)) {
      try {
        const manifest = JSON.parse(readFileSync(candidate, 'utf8')) as { name?: string; version?: string };
        if (manifest.name === 'jeth' && typeof manifest.version === 'string') return manifest.version;
      } catch {
        // Keep searching upward. A malformed unrelated package.json must not break --version.
      }
    }
    const parent = dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  return 'unknown';
}

function safeSolcVersion(): string {
  try {
    return solcVersion();
  } catch {
    return 'unknown';
  }
}

function helpText(): string {
  return `jethc ${packageVersion()} - JETH compiler (solc ${safeSolcVersion()})

Usage:
  jethc <entry.jeth> [options]
  jethc --config <jeth.config.json> [options]
  jethc --standard-json

Options:
  -o, --output <dir>       Write artifacts for every selected contract
  --contract <name>        Select one contract from a multi-contract entry
  --evm-version <name>     Set the solc EVM target (default: cancun)
  --emit <kinds>           Output files: abi,bin,yul,layout,metadata
  --abi                    Print ABI JSON
  --bin                    Print creation and runtime bytecode
  --yul                    Print generated Yul
  --layout                 Print storage layout JSON
  --json                   Print one structured JSON result
  --standard-json          Read a JETH standard JSON request from stdin
  --config <file>          Load entry and output defaults from JSON
  --quiet                  Suppress human success output (requires --output)
  --debug                  Include a stack trace for unexpected internal failures
  -V, --version            Print compiler and solc versions
  -h, --help               Print this help

Exit codes:
  0  success
  1  JETH or backend compilation failed
  2  invalid arguments, configuration, or input files
  3  unexpected internal compiler failure`;
}

function takeOptionValue(argv: string[], index: number, option: string): { value: string; next: number } {
  const value = argv[index + 1];
  if (value === undefined || value === '--' || value.startsWith('-')) {
    throw new CliFailure('usage', `${option} requires a value`, EXIT_USAGE_ERROR);
  }
  return { value, next: index + 1 };
}

function parseEmitKinds(raw: string): Set<EmitKind> {
  const values = raw
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  if (values.length === 0) throw new CliFailure('usage', '--emit requires at least one output kind', EXIT_USAGE_ERROR);
  const emit = new Set<EmitKind>();
  for (const value of values) {
    if (!(EMIT_KINDS as readonly string[]).includes(value)) {
      throw new CliFailure(
        'usage',
        `unknown --emit kind '${value}'; expected ${EMIT_KINDS.join(',')}`,
        EXIT_USAGE_ERROR,
      );
    }
    emit.add(value as EmitKind);
  }
  return emit;
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    printYul: false,
    printAbi: false,
    printBin: false,
    printLayout: false,
    json: false,
    standardJson: false,
    quiet: false,
    debug: false,
    help: false,
    version: false,
  };
  const positional: string[] = [];
  let optionsEnded = false;

  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index]!;
    if (optionsEnded) {
      positional.push(arg);
      continue;
    }
    if (arg === '--') {
      optionsEnded = true;
      continue;
    }
    if (arg === '-h' || arg === '--help') options.help = true;
    else if (arg === '-V' || arg === '--version') options.version = true;
    else if (arg === '--yul') options.printYul = true;
    else if (arg === '--abi') options.printAbi = true;
    else if (arg === '--bin') options.printBin = true;
    else if (arg === '--layout') options.printLayout = true;
    else if (arg === '--json') options.json = true;
    else if (arg === '--standard-json') options.standardJson = true;
    else if (arg === '--quiet') options.quiet = true;
    else if (arg === '--debug') options.debug = true;
    else if (arg === '-o' || arg === '--output') {
      const taken = takeOptionValue(argv, index, arg);
      options.outDir = taken.value;
      index = taken.next;
    } else if (arg.startsWith('--output=')) options.outDir = arg.slice('--output='.length);
    else if (arg === '--contract') {
      const taken = takeOptionValue(argv, index, arg);
      options.contract = taken.value;
      index = taken.next;
    } else if (arg.startsWith('--contract=')) options.contract = arg.slice('--contract='.length);
    else if (arg === '--evm-version') {
      const taken = takeOptionValue(argv, index, arg);
      options.evmVersion = taken.value;
      index = taken.next;
    } else if (arg.startsWith('--evm-version=')) options.evmVersion = arg.slice('--evm-version='.length);
    else if (arg === '--config') {
      const taken = takeOptionValue(argv, index, arg);
      options.configPath = taken.value;
      index = taken.next;
    } else if (arg.startsWith('--config=')) options.configPath = arg.slice('--config='.length);
    else if (arg === '--emit') {
      const taken = takeOptionValue(argv, index, arg);
      options.emit = parseEmitKinds(taken.value);
      index = taken.next;
    } else if (arg.startsWith('--emit=')) options.emit = parseEmitKinds(arg.slice('--emit='.length));
    else if (arg.startsWith('-')) {
      throw new CliFailure('usage', `unknown option '${arg}'`, EXIT_USAGE_ERROR);
    } else positional.push(arg);
  }

  if (positional.length > 1) {
    throw new CliFailure('usage', `expected one entry file, received ${positional.length}`, EXIT_USAGE_ERROR);
  }
  options.input = positional[0];
  if (options.outDir === '') throw new CliFailure('usage', '--output cannot be empty', EXIT_USAGE_ERROR);
  if (options.contract === '') throw new CliFailure('usage', '--contract cannot be empty', EXIT_USAGE_ERROR);
  if (options.evmVersion === '') throw new CliFailure('usage', '--evm-version cannot be empty', EXIT_USAGE_ERROR);
  if (options.configPath === '') throw new CliFailure('usage', '--config cannot be empty', EXIT_USAGE_ERROR);
  return options;
}

function assertPlainObject(value: unknown, what: string): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new CliFailure('input', `${what} must be a JSON object`, EXIT_USAGE_ERROR);
  }
}

function readJsonFile(path: string, what: string): unknown {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new CliFailure('input', `cannot read ${what} '${path}': ${message}`, EXIT_USAGE_ERROR);
  }
  try {
    return JSON.parse(raw) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new CliFailure('input', `invalid JSON in ${what} '${path}': ${message}`, EXIT_USAGE_ERROR);
  }
}

function readConfig(path: string): JethConfig {
  const value = readJsonFile(path, 'configuration');
  assertPlainObject(value, 'configuration');
  const allowed = new Set(['entry', 'outDir', 'contract', 'evmVersion', 'emit']);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new CliFailure('input', `unknown configuration key '${key}'`, EXIT_USAGE_ERROR);
  }
  for (const key of ['entry', 'outDir', 'contract', 'evmVersion'] as const) {
    if (value[key] !== undefined && typeof value[key] !== 'string') {
      throw new CliFailure('input', `configuration '${key}' must be a string`, EXIT_USAGE_ERROR);
    }
  }
  let emit: EmitKind[] | undefined;
  if (value.emit !== undefined) {
    if (!Array.isArray(value.emit) || value.emit.some((item) => typeof item !== 'string')) {
      throw new CliFailure('input', "configuration 'emit' must be an array of output-kind strings", EXIT_USAGE_ERROR);
    }
    emit = [...parseEmitKinds((value.emit as string[]).join(','))];
  }
  return {
    entry: value.entry as string | undefined,
    outDir: value.outDir as string | undefined,
    contract: value.contract as string | undefined,
    evmVersion: value.evmVersion as string | undefined,
    emit,
  };
}

function applyConfig(options: CliOptions, cwd: string): CliOptions {
  if (!options.configPath) return options;
  const configPath = resolve(cwd, options.configPath);
  const config = readConfig(configPath);
  const configDir = dirname(configPath);
  return {
    ...options,
    input: options.input ?? (config.entry ? resolve(configDir, config.entry) : undefined),
    outDir: options.outDir ?? (config.outDir ? resolve(configDir, config.outDir) : undefined),
    contract: options.contract ?? config.contract,
    evmVersion: options.evmVersion ?? config.evmVersion,
    emit: options.emit ?? (config.emit ? new Set(config.emit) : undefined),
  };
}

function virtualPath(root: string, path: string): string {
  const value = relative(root, path).split(sep).join('/');
  return value || basename(path);
}

function readSource(path: string, label: string): string {
  try {
    if (!statSync(path).isFile()) throw new Error('path is not a regular file');
    return readFileSync(path, 'utf8');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new CliFailure('input', `cannot read ${label} '${path}': ${message}`, EXIT_USAGE_ERROR);
  }
}

function relativeImports(source: string, fileName: string): string[] {
  const sourceFile = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true);
  const imports: string[] = [];
  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
    const specifier = statement.moduleSpecifier.text;
    if (specifier.startsWith('./') || specifier.startsWith('../')) imports.push(specifier);
  }
  return imports;
}

function loadProject(input: string, cwd: string): LoadedProject {
  const entryPath = resolve(cwd, input);
  const root = dirname(entryPath);
  const fileName = basename(entryPath);
  const entrySource = readSource(entryPath, 'entry file');
  const sources: Record<string, string> = {};
  const sourceByFile: Record<string, string> = { [fileName]: entrySource };
  const files: string[] = [fileName];
  const visited = new Set<string>([fileName]);

  const visitImports = (absolutePath: string, displayName: string, source: string): void => {
    for (const specifier of relativeImports(source, displayName)) {
      const dependencyPath = resolve(dirname(absolutePath), specifier);
      const dependencyName = virtualPath(root, dependencyPath);
      if (dependencyPath === entryPath) sources[fileName] = entrySource;
      if (visited.has(dependencyName)) continue;
      const dependencySource = readSource(dependencyPath, `import '${specifier}' from ${displayName}`);
      visited.add(dependencyName);
      sources[dependencyName] = dependencySource;
      sourceByFile[dependencyName] = dependencySource;
      files.push(dependencyName);
      visitImports(dependencyPath, dependencyName, dependencySource);
    }
  };

  visitImports(entryPath, fileName, entrySource);
  return { entrySource, fileName, sources, sourceByFile, files };
}

function artifacts(result: CompileResult): CompileResult[] {
  return result.contracts ?? [result];
}

function selectContracts(result: CompileResult, requested?: string): CompileResult[] {
  const available = artifacts(result);
  if (!requested) return available;
  const selected = available.find((artifact) => artifact.contractName === requested);
  if (!selected) {
    throw new CliFailure(
      'usage',
      `contract '${requested}' was not produced; available contracts: ${available.map((item) => item.contractName).join(', ')}`,
      EXIT_USAGE_ERROR,
    );
  }
  return [selected];
}

function jsonArtifact(artifact: CompileResult): Record<string, unknown> {
  return {
    name: artifact.contractName,
    abi: artifact.abi,
    bytecode: {
      creation: artifact.creationBytecode,
      runtime: artifact.runtimeBytecode,
    },
    storageLayout: artifact.storageLayout,
    yul: artifact.yul,
    diagnostics: artifact.diagnostics,
    libraries: artifact.libraries ?? [],
    linkReferences: artifact.linkReferences ?? {},
  };
}

function successJson(
  selected: CompileResult[],
  input: { entry: string; sources: string[] },
  evmVersion: string,
  written?: string[],
): Record<string, unknown> {
  return {
    schemaVersion: STANDARD_JSON_SCHEMA,
    ok: true,
    compiler: {
      name: 'jeth',
      version: packageVersion(),
      solcVersion: safeSolcVersion(),
      evmVersion,
    },
    input,
    contracts: selected.map(jsonArtifact),
    written: written ?? [],
  };
}

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n');
}

function writeArtifacts(
  selected: CompileResult[],
  outDir: string,
  emit: ReadonlySet<EmitKind>,
  metadata: { entry: string; evmVersion: string },
): string[] {
  try {
    mkdirSync(outDir, { recursive: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new CliFailure('input', `cannot create output directory '${outDir}': ${message}`, EXIT_USAGE_ERROR);
  }
  const written: string[] = [];
  const writeText = (path: string, content: string): void => {
    try {
      writeFileSync(path, content);
      written.push(path);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new CliFailure('input', `cannot write artifact '${path}': ${message}`, EXIT_USAGE_ERROR);
    }
  };
  const writeJsonArtifact = (path: string, value: unknown): void => {
    try {
      writeJson(path, value);
      written.push(path);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new CliFailure('input', `cannot write artifact '${path}': ${message}`, EXIT_USAGE_ERROR);
    }
  };

  for (const artifact of selected) {
    const prefix = resolve(outDir, artifact.contractName);
    if (emit.has('abi')) writeJsonArtifact(`${prefix}.abi.json`, artifact.abi);
    if (emit.has('bin')) {
      writeText(`${prefix}.bin`, artifact.creationBytecode + '\n');
      writeText(`${prefix}.runtime.bin`, artifact.runtimeBytecode + '\n');
      for (const library of artifact.libraries ?? []) {
        writeText(`${prefix}.${library.name}.library.bin`, library.creationBytecode + '\n');
        writeText(`${prefix}.${library.name}.library.runtime.bin`, library.runtimeBytecode + '\n');
      }
    }
    if (emit.has('yul')) writeText(`${prefix}.yul`, artifact.yul.endsWith('\n') ? artifact.yul : artifact.yul + '\n');
    if (emit.has('layout')) writeJsonArtifact(`${prefix}.layout.json`, artifact.storageLayout);
    if (emit.has('metadata')) {
      writeJsonArtifact(`${prefix}.metadata.json`, {
        schemaVersion: STANDARD_JSON_SCHEMA,
        compiler: {
          name: 'jeth',
          version: packageVersion(),
          solcVersion: safeSolcVersion(),
          evmVersion: metadata.evmVersion,
        },
        entry: metadata.entry,
        contract: artifact.contractName,
        bytecodeBytes: {
          creation: artifact.creationBytecode.length / 2,
          runtime: artifact.runtimeBytecode.length / 2,
        },
        diagnostics: artifact.diagnostics,
        libraries: artifact.libraries ?? [],
        linkReferences: artifact.linkReferences ?? {},
      });
    }
  }
  return written;
}

function printWarnings(selected: CompileResult[], sourceByFile: Record<string, string>, io: CliIO): void {
  const warnings = selected.flatMap((artifact) => artifact.diagnostics).filter((item) => item.severity === 'warning');
  if (warnings.length === 0) return;
  io.stderr(line(warnings.map((item) => formatDiagnostic(item, sourceByFile[item.file])).join('\n')));
}

function printSelected(selected: CompileResult[], options: CliOptions, io: CliIO): boolean {
  const printKinds = [options.printAbi, options.printBin, options.printYul, options.printLayout].filter(Boolean).length;
  if (printKinds === 0) return false;
  const labelled = selected.length > 1 || printKinds > 1;
  const heading = (artifact: CompileResult, kind: string): void => {
    if (labelled) io.stdout(`== ${artifact.contractName}: ${kind} ==\n`);
  };
  for (const artifact of selected) {
    if (options.printAbi) {
      heading(artifact, 'ABI');
      io.stdout(line(JSON.stringify(artifact.abi, null, 2)));
    }
    if (options.printBin) {
      heading(artifact, 'bytecode');
      io.stdout(`creation: 0x${artifact.creationBytecode}\nruntime:  0x${artifact.runtimeBytecode}\n`);
    }
    if (options.printYul) {
      heading(artifact, 'Yul');
      io.stdout(line(artifact.yul));
    }
    if (options.printLayout) {
      heading(artifact, 'storage layout');
      io.stdout(line(JSON.stringify(artifact.storageLayout, null, 2)));
    }
  }
  return true;
}

function printSummary(selected: CompileResult[], io: CliIO): void {
  for (const artifact of selected) {
    io.stdout(`compiled ${artifact.contractName}:\n`);
    io.stdout(`  ABI entries:       ${artifact.abi.length}\n`);
    io.stdout(`  storage slots:     ${artifact.ir.slotCount}\n`);
    io.stdout(`  creation bytes:    ${artifact.creationBytecode.length / 2}\n`);
    io.stdout(`  runtime bytes:     ${artifact.runtimeBytecode.length / 2}\n`);
  }
}

function compileProject(options: CliOptions, io: CliIO): number {
  if (!options.input) throw new CliFailure('usage', 'no entry file provided', EXIT_USAGE_ERROR);
  if (options.quiet && !options.outDir) {
    throw new CliFailure('usage', '--quiet requires --output', EXIT_USAGE_ERROR);
  }
  if (options.emit && !options.outDir) {
    throw new CliFailure('usage', '--emit requires --output', EXIT_USAGE_ERROR);
  }
  if (
    options.json &&
    (options.printAbi || options.printBin || options.printYul || options.printLayout || options.quiet)
  ) {
    throw new CliFailure('usage', '--json cannot be combined with print flags or --quiet', EXIT_USAGE_ERROR);
  }

  const project = loadProject(options.input, io.cwd);
  const evmVersion = options.evmVersion ?? DEFAULT_EVM_VERSION;
  let result: CompileResult;
  try {
    result = compile(project.entrySource, {
      fileName: project.fileName,
      evmVersion,
      sources: project.sources,
    });
  } catch (error) {
    if (error instanceof CompileError) {
      throw new CliFailure('compile', error.message, EXIT_COMPILE_ERROR, error.diagnostics, project.sourceByFile);
    }
    if (error instanceof SolcError2) throw new CliFailure('compile', error.message, EXIT_COMPILE_ERROR);
    throw error;
  }

  const selected = selectContracts(result, options.contract);
  const outputDirectory = options.outDir
    ? isAbsolute(options.outDir)
      ? options.outDir
      : resolve(io.cwd, options.outDir)
    : undefined;
  const emit = options.emit ?? new Set<EmitKind>(EMIT_KINDS);
  const written = outputDirectory
    ? writeArtifacts(selected, outputDirectory, emit, { entry: project.fileName, evmVersion })
    : [];

  if (options.json) {
    io.stdout(
      line(
        JSON.stringify(
          successJson(selected, { entry: project.fileName, sources: project.files }, evmVersion, written),
          null,
          2,
        ),
      ),
    );
    return EXIT_SUCCESS;
  }

  if (!options.quiet) {
    printWarnings(selected, project.sourceByFile, io);
    const printed = printSelected(selected, options, io);
    if (!printed && !outputDirectory) printSummary(selected, io);
    if (outputDirectory) {
      io.stdout(`wrote ${written.length} artifact file${written.length === 1 ? '' : 's'} to ${outputDirectory}\n`);
    }
  }
  return EXIT_SUCCESS;
}

function parseStandardJson(raw: string): {
  entry: string;
  entrySource: string;
  sources: Record<string, string>;
  sourceByFile: Record<string, string>;
  contract?: string;
  evmVersion: string;
} {
  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new CliFailure('input', `invalid standard JSON input: ${message}`, EXIT_USAGE_ERROR);
  }
  assertPlainObject(value, 'standard JSON input');
  const input = value as StandardJsonInput;
  if (input.language !== undefined && input.language !== 'JETH') {
    throw new CliFailure('input', "standard JSON 'language' must be 'JETH'", EXIT_USAGE_ERROR);
  }
  if (!input.sources) throw new CliFailure('input', "standard JSON requires a 'sources' object", EXIT_USAGE_ERROR);
  assertPlainObject(input.sources, "standard JSON 'sources'");
  if (input.settings !== undefined) assertPlainObject(input.settings, "standard JSON 'settings'");
  const sourceByFile: Record<string, string> = {};
  for (const [name, source] of Object.entries(input.sources)) {
    assertPlainObject(source, `standard JSON source '${name}'`);
    if (typeof source.content !== 'string') {
      throw new CliFailure('input', `standard JSON source '${name}' requires string content`, EXIT_USAGE_ERROR);
    }
    sourceByFile[name] = source.content;
  }
  const names = Object.keys(sourceByFile);
  const entry = input.settings?.entry ?? (names.length === 1 ? names[0] : undefined);
  if (!entry) {
    throw new CliFailure(
      'input',
      'standard JSON settings.entry is required when sources contains multiple files',
      EXIT_USAGE_ERROR,
    );
  }
  const entrySource = sourceByFile[entry];
  if (entrySource === undefined) {
    throw new CliFailure('input', `standard JSON entry '${entry}' does not exist in sources`, EXIT_USAGE_ERROR);
  }
  const sources = { ...sourceByFile };
  delete sources[entry];
  return {
    entry,
    entrySource,
    sources,
    sourceByFile,
    contract: input.settings?.contract,
    evmVersion: input.settings?.evmVersion ?? DEFAULT_EVM_VERSION,
  };
}

function compileStandardJson(io: CliIO): number {
  const input = parseStandardJson(io.readStdin());
  let result: CompileResult;
  try {
    result = compile(input.entrySource, {
      fileName: input.entry,
      sources: input.sources,
      evmVersion: input.evmVersion,
    });
  } catch (error) {
    if (error instanceof CompileError) {
      throw new CliFailure('compile', error.message, EXIT_COMPILE_ERROR, error.diagnostics, input.sourceByFile);
    }
    if (error instanceof SolcError2) throw new CliFailure('compile', error.message, EXIT_COMPILE_ERROR);
    throw error;
  }
  const selected = selectContracts(result, input.contract);
  io.stdout(
    line(
      JSON.stringify(
        successJson(selected, { entry: input.entry, sources: Object.keys(input.sourceByFile) }, input.evmVersion),
        null,
        2,
      ),
    ),
  );
  return EXIT_SUCCESS;
}

function failureJson(failure: CliFailure): Record<string, unknown> {
  return {
    schemaVersion: STANDARD_JSON_SCHEMA,
    ok: false,
    error: {
      kind: failure.kind,
      message: failure.message,
      diagnostics: failure.diagnostics ?? [],
    },
  };
}

function reportFailure(error: unknown, machine: boolean, debug: boolean, io: CliIO): number {
  const failure =
    error instanceof CliFailure
      ? error
      : new CliFailure(
          'internal',
          `unexpected compiler failure: ${error instanceof Error ? error.message : String(error)}`,
          EXIT_INTERNAL_ERROR,
        );
  if (machine) {
    io.stdout(line(JSON.stringify(failureJson(failure), null, 2)));
    return failure.exitCode;
  }
  if (failure.diagnostics && failure.diagnostics.length > 0) {
    io.stderr(
      line(failure.diagnostics.map((item) => formatDiagnostic(item, failure.sourceByFile?.[item.file])).join('\n')),
    );
  } else {
    io.stderr(`error: ${failure.message}\n`);
  }
  if (!(error instanceof CliFailure) && debug && error instanceof Error && error.stack) {
    io.stderr(line(error.stack));
  }
  return failure.exitCode;
}

export function runCli(argv: string[], io: CliIO = defaultIO()): number {
  const machineRequested = argv.includes('--json') || argv.includes('--standard-json');
  const debugRequested = argv.includes('--debug');
  try {
    const parsed = parseArgs(argv);
    if (parsed.help || argv.length === 0) {
      io.stdout(line(helpText()));
      return EXIT_SUCCESS;
    }
    if (parsed.version) {
      io.stdout(`jethc ${packageVersion()}\nsolc ${safeSolcVersion()}\n`);
      return EXIT_SUCCESS;
    }
    if (parsed.standardJson) {
      const incompatible =
        parsed.input ||
        parsed.configPath ||
        parsed.outDir ||
        parsed.contract ||
        parsed.evmVersion ||
        parsed.emit ||
        parsed.printAbi ||
        parsed.printBin ||
        parsed.printYul ||
        parsed.printLayout ||
        parsed.json ||
        parsed.quiet;
      if (incompatible) {
        throw new CliFailure('usage', '--standard-json cannot be combined with file-mode options', EXIT_USAGE_ERROR);
      }
      return compileStandardJson(io);
    }
    return compileProject(applyConfig(parsed, io.cwd), io);
  } catch (error) {
    return reportFailure(error, machineRequested, debugRequested, io);
  }
}

function isDirectExecution(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return pathToFileURL(realpathSync(resolve(entry))).href === import.meta.url;
  } catch {
    return false;
  }
}

if (isDirectExecution()) process.exitCode = runCli(process.argv.slice(2));
