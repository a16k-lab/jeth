# Units, globals, and builtins

JETH exposes EVM execution context and compiler-provided functions. Access affects
inferred mutability.

## Value and time units

JETH does not currently expose Solidity-style numeric suffix expressions such as
`1 ether` or `2 days` through its TypeScript-shaped syntax. Represent values in
explicit base units or use reviewed named constants and branded types:

```typescript
type Wei = Brand<u256>;

class Units {
  static ONE_ETHER: u256 = 1000000000000000000n;
  static ONE_DAY_SECONDS: u256 = 86400n;
}
```

Names such as `wei`, `ether`, and time-unit keywords remain reserved so ordinary
declarations cannot create misleading alternatives.

## Message globals

| Expression | Type | Meaning |
| --- | --- | --- |
| `msg.sender` | `address` | Immediate caller |
| `msg.value` | `u256` | Wei sent with the call |
| `msg.sig` | `bytes4` | First four calldata bytes |
| `msg.data` | `bytes` | Complete calldata view |

`msg.value` is only available in payable contexts. `msg.data` includes the
selector and supports length, indexing, supported slicing, copying, hashing, and
decoding.

## Transaction globals

| Expression | Type | Meaning |
| --- | --- | --- |
| `tx.origin` | `address` | Original transaction sender |

Do not use `tx.origin` for authorization. A malicious intermediary can preserve
the origin while changing the immediate caller.

## Block globals

Supported block data includes:

```typescript
block.timestamp
block.number
block.chainid
block.coinbase
block.basefee
block.gaslimit
block.prevrandao
block.difficulty
```

`block.difficulty` maps to post-merge prevrandao semantics on the configured EVM
target. Block producers can influence some fields within protocol constraints;
do not treat timestamp or prevrandao as an unbiasable randomness source.

## Address and code globals

```typescript
address(this)
account.balance
account.code
account.codehash
isContract(account)
```

Code length is not a reliable proof that an address is permanently an EOA.
Contracts under construction have no deployed runtime code, and account code can
change under protocol/account behavior.

## Gas and block history

```typescript
gasleft()
blockhash(number)
blobhash(index)
```

These expose the corresponding EVM operations and protocol limitations.

## Hash functions

```typescript
keccak256(data)
sha256(data)
ripemd160(data)
```

Inputs must have a supported dynamic bytes representation. Convert or ABI-pack
other values explicitly.

## Modular arithmetic

```typescript
addmod(a, b, modulus)
mulmod(a, b, modulus)
```

A zero modulus follows the compiler's Solidity-compatible panic behavior rather
than silently relying on the raw opcode's zero result.

## ABI helpers

```typescript
abi.encode(a, b)
abi.encodePacked(a, b)
abi.encodeWithSelector(selector, a, b)
abi.encodeWithSignature("f(uint256)", value)
abi.decode(data, u256)
data.decode([u256, address])
```

Standard encoding uses ABI head/tail layout. Packed encoding concatenates the
packed representations and can be ambiguous when more than one dynamic value is
included. Do not use ambiguous packed encodings for signatures or collision-
sensitive hashing.

## Signatures and crypto

```typescript
ecrecover(hash, v, r, s)
recover(hash, signature)
recover(hash, v, r, s)
tryRecover(hash, signature)
```

Raw `ecrecover` matches the EVM/Solidity precompile behavior and can return the
zero address on failure. The safe recovery helpers enforce the documented
signature-length, low-s, and nonzero-signer rules.

Signature verification must also include domain separation, chain/application
context, nonce or replay protection, expiry where applicable, and the intended
signer semantics.

## Other precompiles

JETH exposes typed helpers for supported modular exponentiation, bn256,
pairing, BLAKE2f, and point-evaluation paths. Each helper has strict input and
failure rules. Consult the feature matrix and tests before using a niche
precompile in production.

## Type information

`type(T).min` and `type(T).max` expose integer bounds where supported. Function
`.selector` exposes the canonical selector of an unambiguous ABI function.

## Concatenation and templates

Supported `string.concat` and `bytes.concat` forms concatenate dynamic values.
Template literals are accepted only as documented string-concatenation sugar;
they are not JavaScript template evaluation.
