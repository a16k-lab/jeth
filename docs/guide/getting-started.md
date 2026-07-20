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

The current CLI can print generated Yul, ABI JSON, creation/runtime bytecode,
and storage layout:

```text
usage: jethc <file.jeth> [options]
  --yul       print generated Yul
  --abi       print ABI JSON
  --bin       print creation and runtime bytecode
  --layout    print storage layout
  -o <dir>    write artifacts to a directory
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

The output directory contains ABI, creation bytecode, runtime bytecode, and Yul.
The exact output format is not stable until the public CLI milestone is complete.

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
