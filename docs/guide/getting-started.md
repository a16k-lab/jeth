# Getting started

## Requirements

- Node.js 22
- npm
- A local clone of the JETH repository

JETH is currently pre-release. Use the repository entry point until a versioned
`jethc` package and standalone binary are published.

## Install and verify

```bash
npm install
npm run build
npm test
```

Compile the bundled counter example:

```bash
npm run jethc -- examples/Counter.jeth --abi --bin --layout
```

Write artifacts to a directory:

```bash
npm run jethc -- examples/Counter.jeth -o build/
```

The CLI loads relative imports, handles multi-contract entries, writes complete
artifact sets, and provides human or structured output:

```text
jethc <entry.jeth> [options]
  -o, --output <dir>       write artifacts
  --contract <name>        select one contract
  --evm-version <name>     select the EVM target
  --emit <kinds>           select artifact files
  --abi, --bin, --yul      print compiler outputs
  --layout                 print storage layout JSON
  --json                   emit structured JSON
  --config <file>          load project defaults
  --standard-json          read JSON from stdin
```

## Create a contract

Create `Hello.jeth`:

```jeth
class Hello {
  value: u256 = 0n;

  setValue(next: u256): External<void> {
    this.value = next;
  }

  get readValue(): External<u256> {
    return this.value;
  }
}
```

Compile it:

```bash
npm run jethc -- Hello.jeth -o build/
```

The output directory contains ABI, creation bytecode, runtime bytecode, Yul,
storage layout, and versioned metadata. See
[Compiler, CLI, and tooling](compiler-and-tooling.md) for imports,
multi-contract selection, configuration, standard JSON, and exit codes.

## Read JETH syntax correctly

- Integer literals use BigInt syntax: `1n`, not `1`.
- `u256` means an EVM `uint256`, not a JavaScript number.
- A bare class is a contract.
- A bare field is storage.
- A method returning `External<T>` is externally callable.
- A `get` method is read-only; the compiler infers `pure` or `view`.
- A method without `External<T>` or `Payable<T>` is internal.
- Arithmetic is checked unless it is inside `unchecked: { ... }`.

## Next steps

- Take the [language tour](language-tour.md).
- Browse progressively larger [examples](examples.md).
- Use the [language reference](language-reference.md) for exact syntax.
- Check [SUPPORTED.md](../../SUPPORTED.md) before relying on an advanced shape.
- Read [security considerations](security/considerations.md) and the
  [compiler correctness model](security/compiler-correctness.md) before
  deploying anything.
