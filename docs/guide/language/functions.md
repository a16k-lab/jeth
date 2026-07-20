# Functions

Functions are declared as class methods. Their name, return wrapper, `get` or
`static` modifier, body, and decorators determine visibility, ABI exposure,
mutability, payability, inheritance behavior, and modifier execution.

## Function forms at a glance

| JETH declaration | Visibility | Mutability rule | ABI entry |
| --- | --- | --- | --- |
| `f(): T` | internal | inferred | no |
| `#f(): T` | private | inferred | no |
| `get f(): T` | internal | inferred read-only | no |
| `get #f(): T` | private | inferred read-only | no |
| `f(): External<T>` | external | state-mutating or void check | yes |
| `get f(): External<T>` | external | inferred `pure` or `view` | yes |
| `f(): Payable<T>` | external | payable and state-mutating | yes |
| `static f(): T` | internal | declared `pure` | no |
| `static get f(): External<T>` | external | declared `pure` | yes |

`External<T>` and `Payable<T>` are source-level return markers. They are not
nested runtime values. For example, an `External<u256>` method returns one
`u256` in the ABI.

## Internal functions

A plain method is internal. It is not emitted in the ABI:

```jeth
double(value: u256): u256 {
  return value * 2n;
}
```

Call an internal method by bare name or through `this`:

```jeth
let a: u256 = double(3n);
let b: u256 = this.double(4n);
```

Internal calls are jumps inside the current EVM execution. They preserve the
current `msg.sender`, `msg.value`, storage context, and revert context. They are
not message calls and cannot be wrapped in `try`/`catch`.

Internal functions support direct recursion and mutual recursion. The compiler
computes transitive reachability and effects, including calls through supported
function references.

## Private functions

A leading `#` is JETH's native spelling of Solidity `private`:

```jeth
class Vault {
  #fee(amount: u256): u256 {
    return amount / 100n;
  }

  get quote(amount: u256): External<u256> {
    return amount - this.#fee(amount);
  }
}
```

A private function:

- is callable only from the class that declares it;
- is absent from the ABI;
- cannot be accessed directly by a derived class;
- can still be used by an inherited base implementation executing on a derived
  contract;
- may have the same source name as a private function in a base class because
  the two declarations are distinct;
- lowers like an internal function after compile-time visibility enforcement.

Private functions must be called with `this.#name(...)`. The `#` is part of the
source name and cannot be replaced with a string, computed property, or the
compiler's internal mangled name.

A private function cannot return `External<T>` or `Payable<T>`. Private and ABI
exposure are contradictory, so the compiler rejects the declaration rather than
publishing an obfuscated selector.

Read-only private helpers can use `get`:

```jeth
class Ledger {
  total: u256;

  get #current(): u256 {
    return this.total;
  }

  get snapshot(): External<u256> {
    return this.#current();
  }
}
```

`get #current()` is still private. `get` controls the read-only axis; `#`
controls the visibility axis.

## Static functions

A `static` method has no instance receiver and is declared pure. Call it through
the class name:

```jeth
class Math {
  static square(value: u256): u256 {
    return value * value;
  }

  static get four(): External<u256> {
    return Math.square(2n);
  }
}
```

A static method cannot read instance storage, `this`, environment-dependent
values, or immutables. It can read compile-time constants and call other pure
static methods. A `static` method that violates its declared-pure contract is a
compile-time error.

`static #helper(...)` is a private static helper and is called as
`ClassName.#helper(...)`. A static payable method is rejected because a static
method has no instance context in which to account for received value.

## External functions

`External<T>` exposes a nonpayable ABI entry:

```jeth
set(value: u256): External<void> {
  this.value = value;
}
```

An externally exposed function is a message-call boundary. Calling it by bare
name is rejected. Put reusable logic in an internal helper, or use an explicit
external self-call when new message-call semantics are intended.

An `External<T>` method that returns a non-void value and is read-only must use
`get`. This prevents an ABI function from silently claiming nonpayable
state-mutating behavior while its body is actually `pure` or `view`:

```jeth
get balanceOf(owner: address): External<u256> {
  return this.balances[owner];
}
```

A read-only `External<void>` check is allowed without `get` because it exposes
no value-returning accessor:

```jeth
checkSolvent(): External<void> {
  require(this.assets >= this.liabilities, "insolvent");
}
```

## Read-only functions and inference

`get` declares that a class method is read-only. Despite its TypeScript-shaped
spelling, a JETH `get` method can have parameters:

```jeth
get quote(amount: u256): External<u256> {
  return amount * this.rate;
}
```

The analyzer computes transitive effects:

- no state, immutable, environment, or external reads: `pure`;
- state, immutable, environment, or read-only external access: `view`;
- storage writes, transient writes, logs, value transfer, or mutating calls:
  state-mutating.

The inferred mutability is emitted in the ABI. A `get` body that writes state,
emits an event, transfers value, or reaches another mutating operation is a
compile-time error.

`View<T>` and `Pure<T>` are interface-only markers. A class method has a body, so
its mutability is inferred. Use `get f(): External<T>` for an exposed read-only
implementation.

## Payable functions

`Payable<T>` exposes an ABI entry that accepts ETH:

```jeth
deposit(): Payable<void> {
  this.balance += msg.value;
}
```

`msg.value` is available only where payability permits it. Nonpayable entries
reject nonzero call value before entering the function body. A `get` method
cannot be payable because read-only and value-receiving declarations conflict.

## Parameters

Every parameter has an explicit JETH type:

```jeth
quote(owner: address, amount: u128): u256 {
  return owner == address(0n) ? 0n : u256(amount) * this.rate;
}
```

External reference-type parameters are decoded from calldata. Internal
reference-type parameters follow the accepted memory, storage, or aliasing path
for their shape. See [Data locations and copying](data-locations.md).

Parameter names participate in named-argument calls and diagnostics. Duplicate
parameter names, reserved names, missing types, and unsupported ABI types are
compile-time errors.

## Return values

The declared return type is checked on every reachable return path:

```jeth
read(): [u256, address] {
  return [this.value, this.owner];
}
```

A `void` function can use `return;`. A non-void function must return a compatible
value on every reachable path. Multi-value returns use tuple syntax and ABI
encode each component in order for external functions.

## Default arguments

Trailing internal parameters can have compile-time defaults:

```jeth
fee(amount: u256, bps: u256 = 30n, floor: u256 = 1n): u256 {
  let result: u256 = amount * bps / 10000n;
  return result < floor ? floor : result;
}
```

Defaults are evaluated in declaration context and must satisfy the supported
constant-expression rules. They are checked even if every current call supplies
the argument. External callers still provide the complete ABI parameter list.

## Named arguments

Internal calls can bind arguments by parameter name:

```jeth
let result: u256 = this.fee({ amount: value, bps: 50n });
```

Names must match parameters, cannot be duplicated, and cannot omit a required
parameter. The compiler reorders the arguments to declaration order before
lowering the call.

## Overloading

Functions can be overloaded when parameter signatures distinguish them:

```jeth
scale(value: u256): u256 { return value * 2n; }
scale(value: u256, factor: u256): u256 { return value * factor; }
```

Return type alone does not create a distinct overload. External overloads must
also have distinct canonical ABI selectors. The compiler rejects ambiguous call
resolution and selector collisions.

## Generics

Internal functions can be generic over supported type parameters:

```jeth
identity<T>(value: T): T {
  return value;
}
```

Generics are monomorphized at compile time. Each concrete instantiation is type
checked and lowered as specialized internal code. Generic functions cannot form
a dynamic runtime type system or a generic external ABI.

## Internal function references

Use arrow-type syntax for an internal function reference:

```jeth
inc(value: u256): u256 { return value + 1n; }
dec(value: u256): u256 { return value - 1n; }

apply(fn: (value: u256) => u256, value: u256): u256 {
  return fn(value);
}

get choose(up: bool, value: u256): External<u256> {
  let fn: (value: u256) => u256 = up ? this.inc : this.dec;
  return this.apply(fn, value);
}
```

Supported function references can be stored in locals, state fields, arrays,
and supported structs; passed and returned internally; compared with `==` and
`!=`; and invoked through a matching signature. An unset reference reverts with
`Panic(0x51)` when called.

Function references are not ABI-encodable external function pointers. They
cannot be external parameters or returns, event values, encoded ABI values, or
cast to integers. Taking the address of an exposed or ambiguous overloaded
method is rejected.

Calls through a reference conservatively include the effects of compatible
targets when the compiler infers mutability.

## Function selectors

An unambiguous exposed function reference has a canonical `bytes4` selector:

```jeth
interface Token {
  transfer(to: address, amount: u256): bool;
}

class SelectorReader {
  get transferSelector(): External<bytes4> {
    return Token.transfer.selector;
  }
}
```

Selector lookup on an overloaded name is ambiguous unless the source context
identifies one signature. The compiler also rejects distinct ABI declarations
whose canonical signatures collide to the same four bytes.

## Function decorators

Function decorators add compile-time behavior:

```jeth
@virtual
calculate(value: u256): u256 {
  return value;
}

@nonReentrant
execute(): External<void> {
  // ...
}
```

The supported families are:

- `@virtual` and `@override` for inheritance;
- declared and applied user modifiers;
- `@nonReentrant` for the transient-storage guard;
- advanced proxy, diamond, and library decorators where documented.

Retired visibility and mutability decorators such as `@external`, `@public`,
`@internal`, `@private`, `@view`, and `@pure` are rejected. Use native return
markers, `#`, `get`, and `static` instead.

Decorators are validated at declaration and application sites. An unused
modifier or generic template is still type-checked through the compiler's
standalone validation routes.

## Calls and effects

Effects propagate through internal calls, private calls, function references,
modifiers, and static methods. A pure caller cannot hide a storage read inside a
helper. A modifier's pre-code and post-code contribute to the wrapped
function's inferred mutability.

External calls are separate EVM calls and can reenter. See
[Interfaces and external calls](interfaces-and-calls.md) and
[Security considerations](../security/considerations.md).
