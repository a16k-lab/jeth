# Security considerations

This chapter covers contract-author risks. Compiler correctness is addressed in
the next chapter.

{% hint style="danger" %}
Passing compiler tests does not make an application safe. Production contracts
still require application-specific testing, economic review, deployment review,
and an independent audit.
{% endhint %}

## Reentrancy

External calls transfer control. Update critical state before interaction,
validate invariants after return where necessary, and use `@nonReentrant` for an
appropriate guard boundary.

Do not assume a static-looking interface prevents the callee from calling other
contracts.

## Authorization

Use `msg.sender`, role state, signatures with replay protection, or a reviewed
governance mechanism. Never use `tx.origin` for authorization.

Check authorization on every state-changing entry, including upgrade, pause,
rescue, callback, and initialization paths.

## Arithmetic and precision

Checked integer arithmetic prevents silent overflow outside `unchecked`, but it
does not prevent:

- precision loss from division;
- unfavorable rounding;
- unit confusion;
- economic overflow in an intentionally wide range;
- incorrect fixed-point scaling;
- division before multiplication;
- malicious boundary inputs.

Use branded units, explicit rounding policies, range checks, and reference
vectors.

## Calls and returndata

A low-level call success flag means the EVM call did not revert. It does not mean
the intended application action occurred. Validate returndata and postconditions.

Bubble raw revert data only when exposing the callee's error surface is intended.
Crafted revert bytes can mimic known selectors.

## ABI and signatures

Avoid ambiguous `abi.encodePacked` inputs when hashing multiple dynamic values.
Include domain separation, chain/application context, signer, nonce, action,
parameters, and expiry as needed.

Enforce low-s signatures through the safe recovery helper and reject the zero
address.

## Randomness and block data

Timestamp, coinbase, prevrandao, blockhash, gas, and ordering can be influenced
or predicted to varying degrees. Use a reviewed randomness protocol for valuable
outcomes.

## Denial of service and gas

Loops over user-growing storage can become uncallable. External calls can consume
gas. Large calldata or returndata can increase copy costs. Deep recursion and
large memory allocations can fail.

Bound iteration, use pull patterns, paginate, and make progress resumable where
appropriate.

## Storage and upgrades

Upgradeable systems must preserve field order, packing, inheritance order,
namespaces, and reserved proxy slots. Initialize every proxy exactly once and
protect upgrade authorization.

An implementation constructor does not initialize proxy storage.

## Delegatecall

External libraries, proxies, and diamonds execute code in another account's
storage context. A delegate target can modify any storage slot and act as the
calling contract.

Only delegate to verified code selected by trusted, audited logic.

## Error handling

Use custom errors for expected failures. Use assertions for internal invariants.
Do not ignore low-level call success. Do not rely on revert strings as a stable
machine protocol.

## Compiler and dependency pinning

Pin the JETH version, solc version, EVM target, dependencies, optimizer settings,
and source inputs. Preserve artifacts and hashes. Recompile and re-audit when the
toolchain changes.

## Audit scope

Passing the JETH differential suite does not audit an application. Production
contracts still need invariant tests, fuzzing, economic analysis, deployment
review, key-management review, and an independent audit.
