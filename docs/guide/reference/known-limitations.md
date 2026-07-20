# Supported features and known limitations

JETH's language surface is intentionally evidence-driven. A source shape is
accepted only when its analyzer and backend path are supported.

> [!WARNING] A type being supported in one location or operation does not imply
> every copy, call, return, assignment, hash, or ABI path for that type is
> supported.

## Authoritative matrix

The exhaustive current list is maintained in
[SUPPORTED.md](../../../SUPPORTED.md). It includes supported shapes, deliberate
diagnostics, safer malformed-calldata deviations, and historical parity notes.

## Important current gates

Representative clean rejections include:

- selected element access into a dynamic-array field of a calldata struct;
- selected aggregate parameters/returns through internal calls;
- some memory structs containing dynamic-array fields;
- memory/calldata struct-to-storage copies containing a dynamic array with a
  fixed-inner value-array level;
- selected whole fixed-array element assignments;
- selected static calldata aggregates inside multi-value returns;
- ternaries over dynamic storage aggregates;
- selected nested packed dynamic-array paths;
- remaining pointer-headed memory/decode shapes;
- arbitrary `new Contract(...)` and raw init-code CREATE/CREATE2 deployment
  beyond the structured EIP-1167 clone builtins;
- artifact/CLI presentation gaps such as tuple component JSON and source maps.

The exact diagnostic and compiler revision matter. This summary should not be
used as an admission predicate.

## Why support is path-specific

The same source type can have different runtime representations in storage,
memory, and calldata. Returning a value, assigning it, hashing it, passing it to
an internal function, and storing it can require different transcodes and
aliasing behavior.

Therefore:

```text
type supported in one operation
does not imply
every operation over that type is supported
```

## Workarounds

Safe workarounds are explicit and local:

- read or write supported leaf fields instead of an unsupported whole-value copy;
- move shared logic to a supported internal helper signature;
- select a dynamic storage branch before performing the aggregate operation;
- use a storage source where storage-to-storage copy is supported;
- encode/decode through a documented supported ABI path;
- split a large shape into smaller supported fields.

Never use a workaround that depends on guessed memory offsets or storage slots.

### Unsupported whole-value copy and safe redesign

This shape is intentionally rejected because it contains a dynamic array whose
element is a fixed-size value array:

```jeth
// Expected JETH470-style compile error.
type NestedPairs = {
  tag: u256;
  pairs: Arr<u256, 2>[];
};

class RejectedPairs {
  value: NestedPairs;

  setValue(input: NestedPairs): External<void> {
    this.value = input;
  }
}
```

When changing the application schema is acceptable, flatten the pair data into
a supported dynamic value array and preserve the pair invariant explicitly:

```jeth
class FlatPairs {
  tag: u256;
  values: u256[];

  replace(newTag: u256, flatValues: u256[]): External<void> {
    require(flatValues.length % 2n == 0n, "incomplete pair");
    this.tag = newTag;
    this.values = flatValues;
  }

  get pairCount(): External<u256> {
    return this.values.length / 2n;
  }

  get pairValue(pairIndex: u256, side: u256): External<u256> {
    require(side < 2n, "invalid side");
    return this.values[pairIndex * 2n + side];
  }
}
```

This is a schema change, not a representation trick. Existing protocols should
not silently substitute it for an established ABI.

## Permanently excluded features

JavaScript runtime features without a clear EVM meaning remain rejected. This
includes floating-point `number`, `any`, async/await, generators, closures,
regular expressions, `eval`, implicit coercion, and prototype behavior.

## Versioning

The accepted set can grow as ORs are safely lifted. It must not silently shrink
or change semantics in a stable release without a documented compatibility
decision.
