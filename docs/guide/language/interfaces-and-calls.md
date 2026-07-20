# Interfaces and external calls

Interfaces describe contract-to-contract ABI calls. Low-level address calls are
available when the callee schema is unknown or raw returndata is required.

## Interface declarations

```jeth
interface Oracle {
  price(asset: address): View<u256>;
  decimals(): Pure<u8>;
  update(data: bytes): Payable<void>;
}
```

Interface methods have no body, so mutability cannot be inferred. Use the
supported interface return wrappers to state `pure`, `view`, nonpayable, or
payable behavior.

Interfaces can extend other interfaces. Overloads are allowed when canonical
parameter signatures differ. Events and custom errors may also be declared in
an interface; they do not contribute to its EIP-165 interface ID.

## Selectors and interface IDs

Use a type-qualified member for a function selector:

```jeth
let selector: bytes4 = Oracle.price.selector;
```

For a directly declared contract member, `ContractName.method.selector` and
`this.method.selector` are supported. Internal methods have no ABI selector. An
overloaded name is rejected when the source context does not identify exactly
one signature.

`type(I).interfaceId` returns the XOR of the selectors declared directly by
interface `I`:

```jeth
interface IERC165 {
  supportsInterface(id: bytes4): View<bool>;
}

class C {
  get erc165Id(): External<bytes4> {
    return type(IERC165).interfaceId;
  }
}
```

As in Solidity, inherited interface methods are excluded from the derived
interface's own `interfaceId`. Query each layer when implementing an inheritance
chain. `type(...).interfaceId` is valid for interfaces, not contract, enum, or
integer types.

## Typed interface calls

Convert an address to the interface and call a member:

```jeth
get readPrice(oracle: address, asset: address): External<u256> {
  return Oracle(oracle).price(asset);
}
```

The compiler emits the canonical selector, ABI-encodes arguments, checks call
success, and ABI-decodes the declared result. Contract existence checks follow
the call/decode path's documented behavior.

Build type-checked calldata without making the call using `abi.encodeCall`:

```jeth
let payload: bytes = abi.encodeCall(Oracle.price, [asset]);
```

The function reference must resolve to one unambiguous ABI signature, and the
argument tuple must match that signature.

Typed calls are external EVM calls. `msg.sender` in the callee is the calling
contract, not the original transaction sender.

## External self-calls

Calling an exposed member through `this` is a message call to the current
contract. It changes the call frame and is not equivalent to an internal call.
Use an internal helper when shared code should preserve the current frame.

## Low-level calls

Addresses support checked low-level call forms:

```jeth
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

```jeth
let [ok, result]: [bool, bytes] = target.tryCall({ data: payload });
if (!ok) {
  revertWith(result);
}
```

Always handle both the success flag and returndata. A successful call can return
malformed bytes.

## Decoding returndata

Decode a successful result explicitly:

```jeth
let value: u256 = result.decode(u256);
let [amount, owner]: [u256, address] = result.decode([u256, address]);
```

Supported call options can request decoding directly:

```jeth
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
