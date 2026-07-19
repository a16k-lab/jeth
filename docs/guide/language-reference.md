# Types

JETH is statically typed. Every value has a type known during compilation, and
the type determines its valid operations, storage representation, ABI encoding,
conversion rules, and default value.

This section is split into three detailed chapters:

1. [Value types](language/value-types.md) covers integers, booleans, addresses,
   fixed bytes, enums, brands, and function references.
2. [Reference and composite types](language/reference-types.md) covers dynamic
   bytes/string, arrays, mappings, structs, nested composites, and tuples.
3. [Data locations and copying](language/data-locations.md) covers storage,
   calldata, memory, aliasing, deep copies, dynamic cleanup, and `delete`.

## Type families

| Family | JETH syntax | Main representation |
| --- | --- | --- |
| Unsigned integer | `u8` through `u256` | EVM word, checked arithmetic |
| Signed integer | `i8` through `i256` | Two's-complement EVM word |
| Boolean | `bool` | Strict zero/one ABI word |
| Address | `address` | 160-bit value |
| Fixed bytes | `bytes1` through `bytes32` | Left-aligned byte sequence |
| Dynamic bytes | `bytes` | Dynamic ABI/storage/memory value |
| String | `string` | UTF-8 byte sequence |
| Enum | `enum Name { ... }` | `uint8`-backed nominal type |
| Brand | `type X = Brand<Base>` | Erased nominal value type |
| Dynamic array | `T[]` | Location-dependent reference value |
| Fixed array | `Arr<T, N>` | Inline or aggregate value |
| Mapping | `mapping<K, V>` | Storage-only hashed association |
| Struct | `type P = { ... }` | Ordered fields/ABI tuple |
| Tuple | `[A, B]` | Multiple values |
| Function reference | inferred/supported signature | Internal callable reference |

## No implicit dynamic typing

There is no `any`, runtime union, implicit number/string conversion, truthiness,
`undefined`, or `null`. Conversions must be permitted by the source and target
types and are often explicit.

## Shape and location

Two values with the same source type can use different runtime representations
in storage, calldata, and memory. Compiler support is therefore sometimes
consumer-specific. For example, returning a nested aggregate and copying it to
storage are different operations with different safety requirements.

Continue with [value types](language/value-types.md).
