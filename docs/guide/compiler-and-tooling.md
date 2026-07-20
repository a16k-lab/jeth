# Compiler, CLI, and tooling

The JETH compiler accepts source text, validates and analyzes it, emits Yul and
ABI metadata, then asks solc to optimize and assemble bytecode.

## Current requirements

- Node.js 22
- npm dependencies from the repository lockfile
- the bundled `solc` JavaScript package

JETH is currently pre-release. Use the repository command until the versioned
package and standalone binary are released.

## Command line

```text
jethc <entry.jeth> [options]
jethc --config <jeth.config.json> [options]
jethc --standard-json
```

Run through npm:

```bash
npm run jethc -- examples/Counter.jeth --abi --bin --layout
```

The repository command and the packaged executable use the same implementation:

```bash
npm run jethc -- examples/Counter.jeth --abi --bin --layout
node dist/src/cli.js examples/Counter.jeth -o build/
```

Options:

| Option | Behavior |
| --- | --- |
| `-o`, `--output <dir>` | Write artifacts for every selected contract |
| `--contract <name>` | Select one contract from a multi-contract entry |
| `--evm-version <name>` | Select the solc EVM target, default `cancun` |
| `--emit <kinds>` | Select output files: `abi,bin,yul,layout,metadata` |
| `--yul` | Print generated Yul |
| `--abi` | Print ABI JSON |
| `--bin` | Print creation and runtime bytecode |
| `--layout` | Print storage layout JSON |
| `--json` | Print a structured success or failure result |
| `--standard-json` | Read a JETH standard JSON request from stdin |
| `--config <file>` | Load project defaults from JSON |
| `--quiet` | Suppress human success output when writing artifacts |
| `--debug` | Include a stack for an unexpected internal failure |
| `-V`, `--version` | Print JETH and solc versions |
| `-h`, `--help` | Print complete usage |

Unknown options, missing values, multiple entry files, unreadable files, and
unknown contract names reject instead of being ignored. Without a print or
output option, the CLI prints one summary per compiled contract.

## Filesystem projects and imports

The CLI discovers relative imports recursively from the entry file:

```jeth
import { Ownable } from "./contracts/Ownable.jeth";
import { Math } from "../shared/Math.jeth";
```

Every dependency is passed to the compiler's multi-file bundler. Diagnostics
retain the original file, line, column, and source span. JETH import rules still
apply: imports are named and relative, imported declarations must be exported,
and imported files cannot introduce a deployable contract.

## Multi-contract output

If an entry declares `Alpha` and `Beta`, `-o build/` writes both artifact sets.
Select one explicitly when a deployment flow needs only one contract:

```bash
npm run jethc -- src/Multi.jeth --contract Beta -o build/
```

## Current output files

With `-o build/`, the CLI writes:

```text
Contract.abi.json
Contract.bin
Contract.runtime.bin
Contract.yul
Contract.layout.json
Contract.metadata.json
```

External library objects are written as
`Contract.Library.library.bin` and `Contract.Library.library.runtime.bin` when
present. Hex bytecode files do not include a `0x` prefix. Metadata records the
compiler, solc and EVM versions, byte lengths, diagnostics, libraries, and link
references. The schema is versioned but remains pre-1.0.

Use `--emit` to restrict files:

```bash
npm run jethc -- src/App.jeth -o build/ --emit abi,bin,metadata
```

## Project configuration

`--config` accepts these keys:

```json
{
  "entry": "src/App.jeth",
  "outDir": "build",
  "contract": "App",
  "evmVersion": "cancun",
  "emit": ["abi", "bin", "yul", "layout", "metadata"]
}
```

Paths inside the configuration are relative to the configuration file. Explicit
CLI options override configuration values. Unknown configuration keys reject.
The repository includes `jeth.config.example.json` as a starting point.

## Machine interfaces

`--json` compiles a filesystem project and writes one JSON document containing
the compiler identity, source list, selected contracts, ABI, bytecode, storage
layout, Yul, libraries, link references, and written-file list. Failures use the
same channel and include structured diagnostics.

`--standard-json` reads from stdin. The input shape is:

```json
{
  "language": "JETH",
  "sources": {
    "src/Lib.jeth": { "content": "export static class Lib { ... }" },
    "src/App.jeth": { "content": "import { Lib } from './Lib.jeth'; ..." }
  },
  "settings": {
    "entry": "src/App.jeth",
    "contract": "App",
    "evmVersion": "cancun"
  }
}
```

When `sources` contains one file, `settings.entry` is optional. Standard JSON
always responds with JSON.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success, help, or version output |
| `1` | JETH analysis or solc backend compilation failed |
| `2` | Invalid arguments, configuration, input files, or contract selection |
| `3` | Unexpected internal compiler failure |

## Compiler API

```jeth
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

```jeth
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

```jeth
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

The EVM target is available through `--evm-version`, configuration, the compiler
API, and standard JSON. Optimizer tuning remains fixed until alternative settings
have correctness and gas evidence.

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

## Remaining tooling roadmap

A stable public toolchain still needs:

- source maps and source-level traces;
- reproducible build-info files and content hashes;
- validated optimizer profiles;
- incremental/watch builds;
- package publication and standalone binaries;
- Foundry/Hardhat integration, deployment, linking, and verification;
- LSP and editor tooling.
