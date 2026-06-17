// jethc - the JETH compiler CLI.
//   tsx src/cli.ts <file.jeth> [--yul] [--abi] [--bin] [--layout] [-o out/]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { basename, join } from 'node:path';
import { compile } from './compile.js';
import { CompileError, formatDiagnostics } from './diagnostics.js';
import { solcVersion } from './solc.js';

function main(argv: string[]): void {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    console.log(`jethc - JETH compiler (solc ${safeSolc()})

usage: jethc <file.jeth> [options]
  --yul       print generated Yul
  --abi       print ABI JSON
  --bin       print creation + runtime bytecode
  --layout    print storage layout
  -o <dir>    write Contract.{abi.json,bin,runtime.bin,yul} to <dir>
  (default: print a summary)`);
    return;
  }

  const file = args.find((a) => !a.startsWith('-') && args[args.indexOf(a) - 1] !== '-o');
  if (!file) {
    console.error('error: no input file');
    process.exit(1);
  }
  const outIdx = args.indexOf('-o');
  const outDir = outIdx >= 0 ? args[outIdx + 1] : undefined;

  const source = readFileSync(file, 'utf8');
  let result;
  try {
    result = compile(source, { fileName: basename(file) });
  } catch (e) {
    if (e instanceof CompileError) {
      console.error(formatDiagnostics(e.diagnostics, source));
      process.exit(1);
    }
    throw e;
  }

  if (args.includes('--yul')) console.log(result.yul);
  if (args.includes('--abi')) console.log(JSON.stringify(result.abi, null, 2));
  if (args.includes('--bin')) {
    console.log('creation: 0x' + result.creationBytecode);
    console.log('runtime:  0x' + result.runtimeBytecode);
  }
  if (args.includes('--layout')) console.table(result.storageLayout);

  const printedSomething =
    args.includes('--yul') || args.includes('--abi') || args.includes('--bin') || args.includes('--layout');
  if (!printedSomething && !outDir) {
    console.log(`compiled ${result.contractName}:`);
    console.log(`  functions:        ${result.abi.length}`);
    console.log(`  storage slots:    ${result.ir.slotCount}`);
    console.log(`  creation bytes:   ${result.creationBytecode.length / 2}`);
    console.log(`  runtime bytes:    ${result.runtimeBytecode.length / 2}`);
  }

  if (outDir) {
    mkdirSync(outDir, { recursive: true });
    const n = result.contractName;
    writeFileSync(join(outDir, `${n}.abi.json`), JSON.stringify(result.abi, null, 2));
    writeFileSync(join(outDir, `${n}.bin`), result.creationBytecode);
    writeFileSync(join(outDir, `${n}.runtime.bin`), result.runtimeBytecode);
    writeFileSync(join(outDir, `${n}.yul`), result.yul);
    console.log(`wrote ${n}.{abi.json,bin,runtime.bin,yul} to ${outDir}`);
  }
}

function safeSolc(): string {
  try {
    return solcVersion();
  } catch {
    return '?';
  }
}

main(process.argv);
