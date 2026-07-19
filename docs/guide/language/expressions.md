# Expressions and operators

JETH expressions are statically typed and lower to EVM/Yul operations. They do
not use JavaScript coercion or floating-point semantics.

## Arithmetic

Supported arithmetic operators include:

```text
+  -  *  /  %  **
```

Arithmetic is checked by default. Overflow and underflow revert with
`Panic(0x11)`. Division or modulo by zero reverts with `Panic(0x12)`.

```typescript
let total: u256 = price * quantity;
let average: u256 = total / count;
```

Use `unchecked` for intentional wrapping:

```typescript
unchecked {
  counter += 1n;
}
```

The operand and result types determine the available operation. Addresses,
booleans, bytes, and unrelated brands do not silently become integers.

## Constant expressions

Compile-time arithmetic is evaluated exactly before conversion to the target
integer type. This matches Solidity constant rational behavior.

```typescript
static TEN: u256 = (10n / 4n) * 4n; // 10, not 8.
```

A non-integral final result, division by zero, or value outside the target range
is a compile-time error.

## Comparisons

```text
==  !=  <  <=  >  >=
```

Comparisons require compatible types. Equality is EVM value equality, with no
JavaScript coercion. Address ordering is unsigned. Aggregate equality is not a
general deep-equality operation.

## Boolean operators

```text
!  &&  ||
```

`&&` and `||` short-circuit. The right side is not evaluated when the left side
determines the result.

```typescript
if (denominator != 0n && numerator / denominator > 2n) {
  // The division cannot run when denominator is zero.
}
```

## Bitwise operators and shifts

```text
&  |  ^  ~  <<  >>
```

Bitwise operations apply to compatible integer or fixed-bytes types. Shift
results keep the left operand's type. Signed right shift follows EVM arithmetic
shift behavior.

## Assignment

```text
=  -=  *=  /=  %=  **=  &=  |=  ^=  <<=  >>=
```

Assignment expressions yield the assigned value where supported. Compound
assignment reads, computes, checks, and writes the target.

```typescript
this.total += amount;
let next: u256 = (local += 1n);
```

Prefix and postfix `++`/`--` preserve their usual before/after value distinction.

## Conditional expression

```typescript
let result: u256 = condition ? whenTrue : whenFalse;
```

Only the selected branch executes. Both branches must have compatible types.
Ternaries over many aggregate locations are supported, but dynamic storage
aggregate ternaries remain location-sensitive.

## Member and index access

```typescript
this.user.owner
this.values[i]
this.users[account].positions[j].amount
data.length
```

Runtime array/bytes indices are bounds-checked. Mapping access derives a storage
slot rather than performing an enumeration lookup.

## Calls

JETH distinguishes:

- internal calls to ordinary methods;
- external self-calls;
- typed interface calls;
- qualified and attached library calls;
- low-level address calls;
- compiler builtins.

Each call family has its own mutability, ABI, evaluation-order, and failure
rules. See the functions and external-calls chapters.

## Evaluation order

JETH matches its Solidity target for observable evaluation order:

- binary operands evaluate right-to-left;
- call, event, error, array-literal, and return-tuple arguments evaluate
  left-to-right;
- short-circuit and conditional expressions evaluate only the selected path;
- tuple assignment evaluates the full right side before stores begin.

Avoid writing code whose correctness depends on obscure operand side effects.

## Explicit conversions

Conversions use type-call syntax:

```typescript
let wide: u256 = u256(small);
let account: address = address(raw);
let id: TokenId = TokenId(rawId);
```

Conversions are restricted by source/target kind and width. Explicit narrowing
does not authorize an unsupported cross-kind conversion.
