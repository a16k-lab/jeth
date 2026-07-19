# Compiler, CLI, and tooling

The JETH compiler accepts source text, validates and analyzes it, emits Yul and
ABI metadata, then asks solc to optimize and assemble bytecode.

## Current requirements

- Node.js 22
- npm dependencies from the repository lockfile
- the bundled `solc` JavaScript package

JETH is currently a private pre-release package. Use the repository command until
the public package and standalone binary are released.

## Command line

```text
jethc <file.jeth> [options]
```

Run through npm:

```bash
npm run jethc -- examples/Counter.jeth --abi --bin --layout
```

Current options:

| Option | Behavior |
| --- | --- |
| `--yul` | Print generated Yul |
| `--abi` | Print ABI JSON |
| `--bin` | Print creation and runtime bytecode |
| `--layout` | Print storage layout |
| `-o <dir>` | Write basic artifacts to a directory |
| `-h`, `--help` | Print usage and solc version |

Without an output flag, the CLI prints a compilation summary.

## Current output files

With `-o build/`, the CLI writes:

```text
Contract.abi.json
Contract.bin
Contract.runtime.bin
Contract.yul
```

Hex bytecode files do not include a `0x` prefix. The output schema is not yet a
frozen public artifact standard.

## Compiler API

```typescript
import { compile } from "./src/compile.js";

const result = compile(source, {
  fileName: "Counter.jeth",
  evmVersion: "cancun",
});
```

`CompileOptions` supports:

| Field | Meaning |
| --- | --- |
| `fileName` | Entry file name used in diagnostics and imports |
| `evmVersion` | solc EVM target, default `cancun` |
| `sources` | Multi-file path-to-source map for imports |

`CompileResult` contains:

| Field | Meaning |
| --- | --- |
| `contractName` | Selected artifact name |
| `abi` | ABI items emitted by JETH |
| `creationBytecode` | Creation bytecode, hex without `0x` |
| `runtimeBytecode` | Runtime bytecode, hex without `0x` |
| `yul` | Generated Yul source |
| `storageLayout` | Name/type/slot/offset entries |
| `ir` | Typed compiler IR |
| `diagnostics` | Nonfatal diagnostics |
| `libraries` | Separately deployable external libraries when present |
| `linkReferences` | Library placeholder positions when present |
| `contracts` | All artifacts for a multi-contract source unit |

For a multi-contract file, singular fields describe the first deployable
contract and `contracts` holds artifacts in document order.

## Multi-file API

```typescript
const result = compile(entrySource, {
  fileName: "src/App.jeth",
  sources: {
    "src/App.jeth": entrySource,
    "src/Ownable.jeth": ownableSource,
    "src/Math.jeth": mathSource,
  },
});
```

Import paths resolve against this source map. Diagnostics are remapped to the
original source file and span.

## Diagnostics

Compilation failures throw `CompileError` with structured diagnostics:

```typescript
try {
  const result = compile(source, { fileName: "C.jeth" });
} catch (error) {
  if (error instanceof CompileError) {
    for (const diagnostic of error.diagnostics) {
      // severity, code, message, file, line, column, length
    }
  }
}
```

Use `formatDiagnostics` for terminal output. Tooling should prefer structured
fields over parsing formatted text.

## Pipeline

```text
.jeth source
  -> TypeScript syntax tree
  -> legacy-syntax and subset validation
  -> import bundling and declaration routing
  -> type resolution and semantic analysis
  -> effect/mutability inference
  -> Solidity-compatible storage planning
  -> typed JETH IR
  -> ABI generation
  -> Yul generation
  -> solc optimizer, stack scheduler, and assembler
  -> bytecode and link references
```

The ABI is generated from JETH IR because solc only sees the generated Yul.

## Backend settings

The current backend invokes solc in Yul mode with optimization enabled, 200 runs,
Yul optimization enabled, and the selected EVM version. The default target is
Cancun.

These settings are part of the current compiler behavior but are not yet exposed
as a complete stable CLI configuration surface.

## Compile cache

Set `JETH_COMPILE_CACHE=1` to enable the development Yul-to-bytecode cache:

```bash
export JETH_COMPILE_CACHE=1
npm test
```

The cache key includes full Yul, contract name, EVM version, solc version, and a
cache-format version. Only successful compilations are cached. A read/write
failure falls back to a fresh solc compile.

The normal CLI does not enable the cache automatically.

## Development checks

```bash
npm run build
npm test
npm run format:check
```

Compiler changes should add a focused regression test. Solidity-overlapping
behavior should be checked at deploy and runtime, not compilation alone. The
full suite should also pass with shuffled test-file order.

## Planned production CLI

A stable public toolchain still needs:

- project configuration and filesystem import discovery;
- multi-file CLI builds and contract selection;
- standard JSON input/output;
- stable machine-readable diagnostics and exit codes;
- source maps and source-level traces;
- deterministic artifact manifests and build-info files;
- optimizer and EVM-target controls;
- incremental/watch builds;
- package publication and standalone binaries;
- Foundry/Hardhat integration, deployment, linking, and verification;
- LSP and editor tooling.
