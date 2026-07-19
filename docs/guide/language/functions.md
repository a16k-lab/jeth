# Functions

Functions are contract methods. Their return wrapper, body, and decorators
determine exposure, mutability, payability, inheritance behavior, and modifiers.

## Internal functions

A method without an ABI exposure wrapper is internal:

```typescript
double(value: u256): u256 {
  return value * 2n;
}
```

Call it by bare name or through the supported `this` internal form:

```typescript
let a: u256 = double(3n);
let b: u256 = this.double(4n);
```

Internal functions support recursion and mutual recursion. Supported aggregate
parameters can have memory-reference semantics.

## External functions

`External<T>` exposes a nonpayable ABI entry:

```typescript
set(value: u256): External<void> {
  this.value = value;
}
```

The return wrapper is not the runtime result itself. `External<u256>` means the
function is ABI-exposed and returns a `u256`.

Calling an externally exposed function by bare name is rejected. Put shared
logic in an internal helper, or use an explicit external self-call when message
call semantics are intended.

## Read-only functions and inference

A read-only value-returning class method uses `get`:

```typescript
get total(): External<u256> {
  return this.value + this.fee;
}
```

The analyzer computes transitive effects:

- no state or environment reads: `pure`;
- state/environment reads but no writes: `view`;
- storage/transient/log/call effects: state-mutating.

The inferred mutability is emitted in the ABI. A `get` body that writes state is
a compile-time error.

Interfaces cannot infer a body and therefore use markers such as `View<T>` and
`Pure<T>`.

## Payable functions

`Payable<T>` exposes an entry that accepts ETH:

```typescript
deposit(): Payable<void> {
  this.balance += msg.value;
}
```

`msg.value` is available only where payability permits it. Nonpayable entries
reject nonzero call value.

## Parameters and returns

Parameters and returns are statically typed:

```typescript
quote(owner: address, amount: u128): [u256, bool] {
  return [u256(amount) * this.rate, owner != address(0n)];
}
```

External aggregate parameters are calldata values. External returns are ABI
encoded. Internal aggregates use the location/copy rules of their accepted path.

## Default arguments

Trailing internal parameters can have compile-time defaults:

```typescript
fee(amount: u256, bps: u256 = 30n, floor: u256 = 1n): u256 {
  let result: u256 = amount * bps / 10000n;
  return result < floor ? floor : result;
}
```

Defaults are checked at the declaration even if a call always supplies the
argument. External callers still provide the full ABI parameter list.

## Named arguments

Internal calls can bind arguments by parameter name:

```typescript
let result: u256 = this.fee({ amount: value, bps: 50n });
```

Names must match parameters, cannot be duplicated, and omitted required
parameters are errors. Arguments are lowered to the ordinary positional call
after type checking.

## Overloading

Functions can be overloaded when parameter signatures distinguish them.
Selectors use canonical ABI parameter types. Return type alone does not create a
distinct external selector.

Call resolution considers name, arity, named/default arguments, generic
instantiation, visibility, and implicit conversions. An ambiguous call is a
compile-time error.

## Generics

Internal functions can be generic over supported type parameters:

```typescript
identity<T>(value: T): T {
  return value;
}
```

Generics are monomorphized at compile time. Each concrete instantiation is type
checked and lowered as specialized internal code. They do not create a dynamic
runtime type system or generic external ABI.

## Multiple returns

Use tuple syntax:

```typescript
read(): [u256, address] {
  return [this.value, this.owner];
}

use(): void {
  let [value, owner]: [u256, address] = this.read();
}
```

## Function decorators

Supported decorators include inheritance markers, user modifiers, `@using`, and
`@nonReentrant`:

```typescript
@virtual
calculate(value: u256): u256 {
  return value;
}

@nonReentrant
execute(): External<void> {
  // ...
}
```

Decorators are validated at declaration and application sites. An unused
modifier or generic template is still type-checked through the compiler's
standalone validation routes.

## Calls and effects

Effects propagate through internal calls. A pure caller cannot hide a state read
inside a helper. A modifier's pre/post effects also contribute to the wrapped
function's inferred mutability.

External calls are separate EVM calls and can reenter. See interfaces and
external calls, plus the security chapter.
