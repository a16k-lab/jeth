# Examples

The `examples/` directory contains runnable source programs. Start with small
contracts and move to composite ABI/storage cases.

## Suggested learning order

1. [`Counter.jeth`](../../examples/Counter.jeth): state, checked arithmetic, and
   an external getter.
2. [`Arith.jeth`](../../examples/Arith.jeth): integer operations and panic
   behavior.
3. [`Control.jeth`](../../examples/Control.jeth): branches and loops.
4. [`Globals.jeth`](../../examples/Globals.jeth): `msg`, `block`, and `tx` data.
5. [`Events.jeth`](../../examples/Events.jeth): event topics and data.
6. [`Errors.jeth`](../../examples/Errors.jeth): revert strings and custom errors.
7. [`Arrays.jeth`](../../examples/Arrays.jeth): dynamic arrays.
8. [`FixedArrays.jeth`](../../examples/FixedArrays.jeth): fixed arrays.
9. [`Structs.jeth`](../../examples/Structs.jeth): struct construction and storage.
10. [`Nested.jeth`](../../examples/Nested.jeth): nested state shapes.
11. [`Vault.jeth`](../../examples/Vault.jeth): a larger end-to-end contract.

## Compile an example

```bash
npm run jethc -- examples/Vault.jeth --abi --layout
npm run jethc -- examples/Vault.jeth -o build/vault
```

## Example quality policy

Shipping examples should be:

- small enough to explain one concept clearly;
- compiled in CI;
- paired with runtime assertions when behavior matters;
- explicit about security assumptions;
- free of audit-only names such as `_repro` or `_adv` in the public learning path;
- linked from a guide page that explains expected output.

The repository also contains adversarial and generated examples used for compiler
coverage. They are valuable engineering fixtures but are not tutorials.

## Examples still needed for the public docs

- ERC-20-like token with branded units and custom errors;
- access-controlled vault using checks-effects-interactions;
- typed interface call and `try`/`catch`;
- internal and external library linking;
- proxy deployment and safe upgrade walkthrough;
- diamond deployment and selector management;
- calldata slicing plus ABI decoding;
- signed-message recovery with replay protection;
- fixed-point math with explicit rounding once the audited math package exists.
