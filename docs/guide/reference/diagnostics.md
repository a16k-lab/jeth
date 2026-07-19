# Compiler diagnostics

JETH diagnostics identify source spans and use codes such as `JETH470`.

## Reading a diagnostic

A diagnostic normally contains:

- a stable-looking code;
- source file and span;
- a human explanation;
- sometimes the supported alternative or reason for a safety gate.

```text
file.jeth:line:column JETH470 copy to storage not supported for this shape
```

The public machine-readable diagnostic schema and code stability policy are not
yet frozen. Tooling should not parse human prose as a permanent API.

## Diagnostic categories

Diagnostics cover:

- unsupported TypeScript syntax;
- reserved or duplicate declarations;
- unknown names and members;
- type mismatch and invalid conversion;
- visibility/mutability/payability violations;
- invalid inheritance, override, interface, or library structure;
- ABI, calldata, memory, or storage shape restrictions;
- unsupported copy/aliasing paths;
- constructor, immutable, or modifier rules;
- call and return arity;
- constant evaluation and range errors;
- backend soundness guards.

## Clean rejection is intentional

A "not supported" diagnostic is preferable to accepted source that would produce
wrong bytes. Do not suppress or work around such an error by changing types until
the resulting semantics are understood.

## Filing a compiler issue

Include:

1. exact JETH revision/version;
2. exact Node and solc versions;
3. minimal JETH source;
4. Solidity mirror when applicable;
5. full diagnostic or runtime bytes;
6. deploy/call inputs;
7. expected and actual return/revert/log/storage data;
8. deterministic seed for generated failures.

Classify whether the report is a possible MC, OA, OR, diagnostic-quality issue,
or flake. The compiler team should confirm the classification from executable
evidence.
