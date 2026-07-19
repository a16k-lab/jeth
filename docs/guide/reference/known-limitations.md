# Supported features and known limitations

JETH's language surface is intentionally evidence-driven. A source shape is
accepted only when its analyzer and backend path are supported.

{% hint style="warning" %}
A type being supported in one location or operation does not imply every copy,
call, return, assignment, hash, or ABI path for that type is supported.
{% endhint %}

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

## Permanently excluded features

JavaScript runtime features without a clear EVM meaning remain rejected. This
includes floating-point `number`, `any`, async/await, generators, closures,
regular expressions, `eval`, implicit coercion, and prototype behavior.

## Versioning

The accepted set can grow as ORs are safely lifted. It must not silently shrink
or change semantics in a stable release without a documented compatibility
decision.
