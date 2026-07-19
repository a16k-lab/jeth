# Interfaces and external calls

Interfaces describe contract-to-contract ABI calls. Low-level address calls are
available when the callee schema is unknown or raw returndata is required.

## Interface declarations

```typescript
interface Oracle {
  price(asset: address): View<u256>;
  decimals(): Pure<u8>;
  update(data: bytes): Payable<void>;
}
```

Interface methods have no body, so mutability cannot be inferred. Use the
supported interface return wrappers to state `pure`, `view`, nonpayable, or
payable behavior.

## Typed interface calls

Convert an address to the interface and call a member:

```typescript
get readPrice(oracle: address, asset: address): External<u256> {
  return Oracle(oracle).price(asset);
}
```

The compiler emits the canonical selector, ABI-encodes arguments, checks call
success, and ABI-decodes the declared result. Contract existence checks follow
the call/decode path's documented behavior.

Typed calls are external EVM calls. `msg.sender` in the callee is the calling
contract, not the original transaction sender.

## External self-calls

Calling an exposed member through `this` is a message call to the current
contract. It changes the call frame and is not equivalent to an internal call.
Use an internal helper when shared code should preserve the current frame.

## Low-level calls

Addresses support checked low-level call forms:

```typescript
let result: bytes = target.call({
  data: payload,
  value: amount,
  gas: gasLimit,
  success: { condition: this.allowed, revert: "call failed" },
});
```

The exact option set depends on `call` versus `staticcall`. A static call cannot
send value or perform state changes in the callee.

`tryCall` and `tryStaticcall` expose raw success and returndata without automatic
failure bubbling:

```typescript
let [ok, result]: [bool, bytes] = target.tryCall({ data: payload });
if (!ok) {
  revertWith(result);
}
```

Always handle both the success flag and returndata. A successful call can return
malformed bytes.

## Decoding returndata

Decode a successful result explicitly:

```typescript
let value: u256 = result.decode(u256);
let [amount, owner]: [u256, address] = result.decode([u256, address]);
```

Supported call options can request decoding directly:

```typescript
let value: u256 = target.staticcall({
  data: abi.encodeWithSignature("read()"),
  success: { condition: this.allowed, revert: "read failed" },
  decode: u256,
});
```

ABI decode validates offsets, lengths, and value words for the requested type.

## `try`/`catch`

Use `try`/`catch` when the syntax and return shape are clearer than manual raw
data handling. Catch clauses can inspect supported `Error(string)`, panic, and
raw failure forms.

## Revert bubbling

`revertWith(data)` reverts with the exact bytes returned by a failed call. This
preserves custom errors and nonstandard revert payloads.

## Call security

Any external call can transfer control to untrusted code. The callee can:

- reenter the caller;
- consume gas;
- return malformed data;
- return success with an unexpected semantic result;
- deliberately revert with crafted bytes;
- call other contracts before returning.

Update critical state before interaction where possible, validate returned
values, use a reentrancy guard where appropriate, and do not use `tx.origin` for
authorization.
