# JETH Syntax (VS Code)

Syntax highlighting for JETH (`.jeth`) source files - a TypeScript-subset smart-contract
language that compiles to EVM bytecode.

It registers a dedicated `jeth` language (so `.jeth` files are no longer plain text), gives
`.jeth` files the **JETH gradient logo** as their file icon, and ships a TextMate grammar that:

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
cp -R tools/jeth-vscode ~/.vscode/extensions/jeth-syntax-0.2.0
# then in VS Code: Cmd/Ctrl+Shift+P -> "Developer: Reload Window"
```

Open any `.jeth` file (e.g. `examples/Vault.jeth`); it should now be colorful. The language
indicator in the status bar should read "JETH", and the file gets the JETH gradient logo icon
in the Explorer and editor tabs.

To uninstall: remove `~/.vscode/extensions/jeth-syntax-0.2.0` and reload the window.

## The `.jeth` file icon

`icons/jeth-icon-gradient.svg` (the gradient mark from the brand kit) is contributed as the
language icon (`contributes.languages[].icon`). Being SVG it is resolution-independent, so it
stays crisp from the 16px Explorer glyph up to any size. The same artwork (the 1024px PNG) is
the extension's Marketplace icon.

The language icon is shown by any file icon theme that defers to language icons - including the
built-in default, **Seti** (which has no `.jeth` icon of its own, so it uses ours), and
**Minimal**. If you use a third-party icon theme (e.g. Material Icon Theme) that hardcodes its
own set, that theme would need to add a `jeth` mapping for the logo to appear; this is a
limitation of how VS Code icon themes work, not of the extension.

## Notes

- Prettier formatting of `.jeth` still works (configured in the repo's `.prettierrc.json` via a
  `*.jeth` -> `babel-ts` parser override); the two are independent.
- The grammar is purely syntactic (regex/TextMate); it does not type-check.
