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

```jeth
let total: u256 = price * quantity;
let average: u256 = total / count;
```

Use `unchecked` for intentional wrapping:

```jeth
unchecked: {
  counter += 1n;
}
```

The operand and result types determine the available operation. Addresses,
booleans, bytes, and unrelated brands do not silently become integers.

## Constant expressions

Compile-time arithmetic is evaluated exactly before conversion to the target
integer type. This matches Solidity constant rational behavior.

```jeth
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

```jeth
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
=  +=  -=  *=  /=  %=  **=  &=  |=  ^=  <<=  >>=
```

Assignment expressions yield the assigned value where supported. Compound
assignment reads, computes, checks, and writes the target.

```jeth
this.total += amount;
let next: u256 = (local += 1n);
```

Prefix and postfix `++`/`--` preserve their usual before/after value distinction.
Both forms use checked arithmetic outside `unchecked`.

## Tuple destructuring and assignment

Destructure a multi-value result or tuple literal into new locals:

```jeth
let [value, , owner]: [u256, bool, address] = this.readRecord();
```

Assign existing value lvalues and skip unwanted components:

```jeth
[this.left, , local] = this.readRecord();
[a, b] = [b, a];
```

The entire right side is evaluated before any left-side store begins. This makes
swaps deterministic and prevents an early assignment from changing a later
right-side component. Destructuring currently supports the documented value
component paths; it is not JavaScript iterable destructuring.

## Literals and construction

Array literals are contextually typed:

```jeth
let pair: Arr<u256, 2> = [1n, 2n];
let values: u256[] = [1n, 2n, 3n];
```

Structs support positional construction and named object construction:

```jeth
let a: User = User(7n, msg.sender);
let b: User = { id: 8n, owner: msg.sender };
let c: User = { ...b, id: 9n };
```

`new Array<T>(length)` allocates a supported dynamic memory array. JETH does not
use Solidity's `new T[](length)` spelling. Element and nested shapes remain
subject to the documented memory-layout gates.

## Conditional expression

```jeth
let result: u256 = condition ? whenTrue : whenFalse;
```

Only the selected branch executes. Both branches must have compatible types.
Ternaries over many aggregate locations are supported, but dynamic storage
aggregate ternaries remain location-sensitive.

## Member and index access

```jeth
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

```jeth
let wide: u256 = u256(small);
let account: address = address(raw);
let id: TokenId = TokenId(rawId);
```

Conversions are restricted by source/target kind and width. Explicit narrowing
does not authorize an unsupported cross-kind conversion.
