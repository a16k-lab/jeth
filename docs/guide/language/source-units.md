# Source units and imports

A JETH source unit is a UTF-8 text file, conventionally ending in `.jeth`. JETH
uses the TypeScript parser to obtain a syntax tree, then validates a strict
on-chain subset. Being valid TypeScript syntax does not make a construct valid
JETH.

## Top-level declarations

A source unit can contain:

- imports and exports;
- struct-like type aliases;
- branded value-type aliases;
- event and error type aliases;
- enums;
- interfaces;
- abstract and deployable classes;
- static classes used as libraries.

```jeth
import { Ownable } from "./Ownable.jeth";
import { MathLib as Math } from "./Math.jeth";

export type Position = {
  owner: address;
  amount: u256;
};

export enum Status {
  Pending,
  Active,
  Closed,
}

export class Vault extends Ownable {
  // Contract members.
}
```

## Imports

JETH supports named imports from other JETH source units. Imports are resolved
by the compiler's source bundle rather than by Node.js at runtime. Imported
declarations participate in type checking, inheritance, interface conformance,
library resolution, and selector collision checks.

```jeth
import { Base, TokenId } from "./base.jeth";
import { Base as Parent } from "./other.jeth";
```

Use aliases when two modules export the same source name. Duplicate declarations
that remain ambiguous are compile-time errors.

The current command-line interface accepts one entry file. The compiler API can
receive a source map for multi-file builds. A public project configuration and
filesystem import resolver are part of the CLI roadmap.

## Exports

Use `export` on declarations intended for another source unit:

```jeth
export type UserId = Brand<u256>;

export abstract class Owned {
  owner: address;
}
```

An imported contract or abstract class is not automatically deployed. Artifact
production follows deployable leaf classes and library routes in the complete
compilation unit.

## Comments

Line and block comments use TypeScript syntax:

```jeth
// One line.

/*
 * Several lines.
 */
```

NatSpec-compatible artifact documentation is not yet a stable JETH output. Do
not assume comments are currently included in ABI or metadata artifacts.

## Native syntax only

JETH previously used structural decorators such as `@contract`, `@state`, and
`@external`. Those forms are removed. Modern JETH uses native declarations:

```jeth
class C {
  value: u256;

  set(value: u256): External<void> {
    this.value = value;
  }
}
```

The decorators that remain are decorators with real language meaning and no
native TypeScript spelling, including `@virtual`, `@override`, `@modifier`,
user modifier applications, `@using`, `@nonReentrant`, and proxy/diamond
declarations.

## File and declaration names

The compiler tracks declarations by source name and rejects duplicate or
ambiguous declarations. Reserved language, EVM, and compiler names cannot be
used as declarations where they would conflict with syntax or generated
behavior.

One source unit can emit multiple contract and library artifacts. Consumers
should select artifacts by name, not assume the file name is the only contract
name.

## Permanently excluded source behavior

JETH does not provide runtime JavaScript or TypeScript. Constructs such as
`number`, `any`, async/await, promises, generators, closures, regular
expressions, `eval`, prototypes, `typeof`, `instanceof`, and implicit coercion
have no JETH runtime meaning and are rejected.
