# JETH Syntax (VS Code)

Syntax highlighting for JETH (`.jeth`) source files - a TypeScript-subset smart-contract
language that compiles to EVM bytecode.

It registers a dedicated `jeth` language (so `.jeth` files are no longer plain text) and a
TextMate grammar that:

- layers JETH-specific colors on top of the full TypeScript grammar (`source.ts`): the sized
  integer types (`u8`..`u256`, `i8`..`i256`), `bytesN`, `address`/`bool`/`string`/`void`, the
  type constructors `mapping`/`Arr`/`Brand`, the decorators (`@contract`, `@external`, `@view`,
  `@state`, `@event`, `@error`, `@interface`, ...), the global objects (`msg`/`block`/`tx`/`abi`)
  and their members, and the builtins (`keccak256`, `require`, `revert`, `emit`, ...).
- attaches **no language server**, so there are no spurious "Cannot find name 'u256'" type
  errors that a plain `*.jeth` -> TypeScript association would produce.

## Install (local, unpublished)

Copy this folder into your VS Code extensions directory and reload:

```sh
cp -R tools/jeth-vscode ~/.vscode/extensions/jeth-syntax-0.1.0
# then in VS Code: Cmd/Ctrl+Shift+P -> "Developer: Reload Window"
```

Open any `.jeth` file (e.g. `examples/Vault.jeth`); it should now be colorful. The language
indicator in the status bar should read "JETH".

To uninstall: remove `~/.vscode/extensions/jeth-syntax-0.1.0` and reload the window.

## Notes

- Prettier formatting of `.jeth` still works (configured in the repo's `.prettierrc.json` via a
  `*.jeth` -> `babel-ts` parser override); the two are independent.
- The grammar is purely syntactic (regex/TextMate); it does not type-check.
