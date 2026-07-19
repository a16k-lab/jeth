# Function modifiers

Modifiers wrap a function or constructor body with reusable checks and effects.

## Declaration

```typescript
class Owned {
  owner: address;

  @modifier
  onlyOwner() {
    require(msg.sender == this.owner, "not owner");
    _;
  }
}
```

`_` is the placeholder for the wrapped inner body. The identifier is reserved
inside modifier syntax.

## Application

Apply a modifier by name:

```typescript
@onlyOwner
setOwner(next: address): External<void> {
  this.owner = next;
}
```

Modifier arguments evaluate once before the modifier body uses them:

```typescript
@modifier
minimum(value: u256, min: u256) {
  require(value >= min, "below minimum");
  _;
}

@minimum(amount, 10n)
deposit(amount: u256): External<void> {
  this.total += amount;
}
```

## Pre-code and post-code

Statements before `_` execute before the function body. Statements after `_`
execute after every normal body completion, including an early body return.

```typescript
@modifier
countCalls() {
  this.entered += 1n;
  _;
  this.exited += 1n;
}
```

If the wrapped body reverts, the whole call reverts and post-code does not commit
state.

## Multiple modifiers

Modifiers nest leftmost-outermost:

```typescript
@outer
@inner
run(): External<void> {
  // body
}
```

The conceptual order is `outer-pre`, `inner-pre`, body, `inner-post`,
`outer-post`.

## Conditional or repeated placeholders

A modifier can execute `_` conditionally or more than once on supported shapes.
This changes whether and how often the wrapped body runs. Treat such modifiers as
control-flow constructs, not only validation macros.

## Return behavior

A body `return` stores the return value, finishes the body layer, then runs
modifier post-code before final ABI encoding.

A bare `return;` in a modifier exits that modifier layer only. An enclosing
modifier resumes after its own `_`. This distinction is important for nested
modifiers.

## Constructor modifiers

Modifiers can wrap constructors:

```typescript
@validOwner(owner)
constructor(owner: address) {
  this.owner = owner;
}
```

Constructor modifier execution participates in base/derived construction and
immutable staging rules.

## Effects and type checking

Modifier effects contribute to the wrapped function's mutability. A modifier
that writes storage cannot be hidden inside a read-only `get`.

Declared but unapplied modifiers are still type-checked. Generic modifier bodies
are validated against real reachable types and checked again at application
sites.

## `@nonReentrant`

JETH includes a built-in transient-storage guard:

```typescript
@nonReentrant
withdraw(amount: u256): External<void> {
  // checks
  // effects
  // interaction
}
```

It uses EIP-1153 transient storage, consumes no persistent storage slot, and
reverts on guarded re-entry. It can protect state-mutating external entries.

The guard does not replace checks-effects-interactions, authorization, invariant
tests, or review. All guarded functions share the compiler-defined guard domain,
so calling one guarded entry from another can intentionally reject.
