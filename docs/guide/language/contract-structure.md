# Structure of a contract

Contracts use class syntax. A deployable leaf class becomes an EVM contract
artifact.

```jeth
class SimpleStorage {
  value: u256;

  set(next: u256): External<void> {
    this.value = next;
  }

  get read(): External<u256> {
    return this.value;
  }
}
```

A contract can contain state variables, constants, immutables, functions,
constructors, modifiers, events, errors, and inherited members.

## State variables

Bare fields are persistent storage:

```jeth
class Ledger {
  total: u256;
  balances: mapping<address, u256>;
  names: string[];
}
```

The storage planner assigns Solidity-compatible slots and packed byte offsets.
Field order is therefore part of an upgradeable contract's storage interface.

An initializer executes during contract creation:

```jeth
class C {
  count: u256 = 1n;
  enabled: bool = true;
}
```

### Private state variables

A leading `#` makes a field private to its declaring class:

```jeth
class Vault {
  #assets: u256;

  deposit(amount: u256): External<void> {
    this.#assets += amount;
  }

  get totalAssets(): External<u256> {
    return this.#assets;
  }
}
```

Private state still occupies an ordinary storage position according to
declaration and inheritance order. Privacy is compile-time access control, not
storage secrecy. Anyone can inspect contract storage off chain.

A derived class cannot directly read or write a base class's private field. A
base implementation inherited by that derived class can still access the field.
Base and derived classes may each declare the same `#name`; the declarations are
distinct storage variables.

A private field cannot use `Visible<T>` because private storage and an external
getter conflict.

## Public getters

Wrap a state type in `Visible<T>` to generate an external getter:

```jeth
class C {
  owner: Visible<address>;
  balances: Visible<mapping<address, u256>>;
}
```

Getter parameters and return values follow Solidity's public-state-getter rules
for the supported storage shape. The underlying field remains available to
contract code.

`Visible<T>` can also wrap a supported initialized constant or immutable field,
producing an external read-only getter without allocating a storage slot.

## Constants

An initialized `static` field is a compile-time constant. It consumes no storage
slot and is folded at each use site.

```jeth
class Units {
  static BPS: u256 = 10000n;

  get half(): External<u256> {
    return Units.BPS / 2n;
  }
}
```

Constants must have compiler-foldable initializers. Constant expressions use
exact rational semantics before conversion to the target integer type.

## Immutables

A `static` value field without an initializer is an immutable. Assign it in the
constructor. It is baked into runtime bytecode and consumes no storage slot.

```jeth
class Token {
  static OWNER: address;

  constructor(owner: address) {
    this.OWNER = owner;
  }

  get owner(): External<address> {
    return this.OWNER;
  }
}
```

Only supported value types can be immutable. An immutable cannot be reassigned
after construction.

## Functions

Return wrappers define ABI exposure:

```jeth
helper(x: u256): u256 { return x + 1n; }
#privateHelper(x: u256): u256 { return x + 2n; }
static pureHelper(x: u256): u256 { return x + 3n; }
set(x: u256): External<void> { this.value = x; }
get read(): External<u256> { return this.value; }
deposit(): Payable<void> { this.total += msg.value; }
```

- No wrapper means internal.
- A leading `#` means private to the declaring class.
- `static` declares a method pure and removes the instance receiver.
- `External<T>` means externally callable and nonpayable.
- `Payable<T>` means externally callable and payable.
- A read-only value-returning class method uses `get`; its `pure` or `view`
  mutability is inferred from transitive effects.

## Events and errors

Events and errors can be declared at file scope or as members:

```jeth
class Vault {
  Deposited: event<{ account: indexed<address>; value: u256 }>;
  Unauthorized: error<{ caller: address }>;
}
```

Use `emit` for events and `revert` or `require` for errors.

## Constructor

The constructor runs once in creation code. It can accept ABI-encoded arguments,
initialize state and immutables, call supported internal functions, and invoke a
base constructor.

```jeth
class C {
  owner: address;

  constructor(owner: address) {
    this.owner = owner;
  }
}
```

A constructor is nonpayable unless decorated with `@payable`.

## Special entries

A method named `receive` handles empty calldata and accepts value. A method named
`fallback` handles selectors not matched by ordinary entries. Their accepted
parameters and return behavior follow the JETH special-entry rules.

```jeth
class Receiver {
  received: u256;

  receive(): void {
    this.received += msg.value;
  }

  fallback(): void {
    this.received += 1n;
  }
}
```

`receive()` is payable by definition. A plain `fallback(): void` is nonpayable;
use `fallback(): Payable<void>` when the fallback must accept and read value.

The supported fallback forms are:

```jeth
fallback(): void { }
fallback(): External<void> { }
fallback(): Payable<void> { }
fallback(input: bytes): bytes { return input; }
fallback(input: bytes): Payable<bytes> { return input; }
```

The `External<T>` wrapper is optional and redundant on a nonpayable fallback.
A data-passing fallback receives the complete calldata and returns raw bytes.
There can be at most one `receive` and one `fallback`. `receive` takes no
parameters, returns no value, and must not use `Payable<T>` because it is already
payable by definition.

## Abstract contracts, interfaces, and libraries

```jeth
abstract class Base {
  abstract value(): External<u256>;
}

interface Oracle {
  price(asset: address): View<u256>;
}

static class MathLib {
  min(a: u256, b: u256): u256 {
    return a < b ? a : b;
  }
}
```

These declaration kinds are covered in their dedicated chapters.
