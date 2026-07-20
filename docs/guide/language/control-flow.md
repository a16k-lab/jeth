# Statements and control flow

JETH has structured control flow with EVM-compatible return and revert behavior.

## Blocks and scope

Braces create a lexical scope:

```jeth
let value: u256 = 1n;
{
  let value: u256 = 2n;
  // Inner value shadows outer value.
}
```

A nested declaration can shadow an outer name. Redeclaring a name in the same
scope is an error. The compiler assigns unique internal names so source
shadowing does not become Yul shadowing.

## Conditional statements

```jeth
if (amount == 0n) {
  return;
} else if (amount > limit) {
  revert("too large");
} else {
  this.total += amount;
}
```

Conditions must be `bool`. There is no integer truthiness.

## `while` and `do...while`

```jeth
while (i < count) {
  i += 1n;
}

do {
  i -= 1n;
} while (i != 0n);
```

`while` checks before the body. `do...while` executes the body at least once.

## Classic `for`

```jeth
for (let i: u256 = 0n; i < values.length; i += 1n) {
  sum += values[i];
}
```

The initializer, condition, and update use their usual structured order. A
missing condition is treated as true where the syntax is accepted.

## `for...of`

`for...of` iterates supported storage, calldata, memory, or fixed arrays:

```jeth
for (const value of values) {
  sum += value;
}
```

The desugaring re-reads array length and the current element on each iteration.
Mutation of a storage array during iteration therefore affects subsequent
iterations as it would in the equivalent indexed loop.

`for...in` is rejected.

## `break` and `continue`

`break` exits the nearest loop. `continue` starts its next iteration. Labeled
break and continue are not part of JETH.

## `switch`

JETH adds a structured switch that Solidity source does not have:

```jeth
switch (state) {
  case State.Pending:
    return 0n;
  case State.Active:
    return 1n;
  case State.Closed:
    return 2n;
}
```

The discriminant is evaluated once. A non-empty case cannot fall through
implicitly. An empty case label can share the next case body. Enum switches
without `default` must cover every enum member.

Duplicate constant cases and non-terminating accidental fallthrough are
compile-time errors.

## Return

```jeth
return;
return value;
return [first, second];
```

Return type and arity are checked. A function that reaches its end returns its
type's zero value where Solidity does. Modifier post-code still executes around
an early function-body return according to modifier nesting.

## Revert and require

```jeth
require(owner == msg.sender);
require(balance >= amount, "insufficient balance");
revert();
revert("disabled");
revert(Unauthorized(msg.sender));
```

An empty revert has no data. A string reason uses `Error(string)`. A custom error
uses its four-byte selector and ABI arguments.

`assert(condition)` represents an internal invariant and reverts with
`Panic(0x01)` when false.

## `try` and `catch`

Supported external calls can be handled with `try`/`catch`. Catch clauses can
distinguish ordinary error strings, panic codes, and raw failure data according
to the supported syntax.

Use raw data handling when the callee is untrusted or can return nonstandard
revert data.

## `delete`

`delete` resets a supported local or storage location to its zero value. Its
behavior depends on storage packing and aggregate shape. See data locations and
storage layout.
