# Libraries and `using`

Libraries use `static class` syntax. They can contain internal inlined functions,
constants, events/errors, modifiers, and supported external functions.

## Internal libraries

```jeth
static class MathLib {
  min(a: u256, b: u256): u256 {
    return a < b ? a : b;
  }
}

class C {
  get smaller(a: u256, b: u256): External<u256> {
    return MathLib.min(a, b);
  }
}
```

Internal library functions are inlined or lowered as internal code with no
deployed library address. Their behavior is compared with Solidity internal
library calls.

## Library constants

```jeth
static class Units {
  static BPS: u256 = 10000n;
  static HALF: u256 = BPS / 2n;
}

class C {
  get half(): External<u256> {
    return Units.HALF;
  }
}
```

Sibling constant dependencies can use bare or qualified names, including
forward references. Cyclic dependencies reject at compile time.

## `@using`

Attach library functions to a receiver type:

```jeth
static class MathLib {
  min(a: u256, b: u256): u256 {
    return a < b ? a : b;
  }
}

@using(MathLib)
class C {
  get smaller(a: u256, b: u256): External<u256> {
    return a.min(b);
  }
}
```

The receiver becomes the first library argument. Multiple libraries can be
listed in one `@using` or stacked applications. Attachment is type-directed.
If an attached name collides with a genuine built-in member such as array
`.length`, the built-in wins; call the library function by its qualified name.

## Native `self` attachment

A library author can make a function attachable without requiring `@using` on
the consuming contract. Name the first parameter exactly `self`:

```jeth
static class MathLib {
  min(self: u256, other: u256): u256 {
    return self < other ? self : other;
  }
}

class C {
  get smaller(a: u256, b: u256): External<u256> {
    return a.min(b);
  }
}
```

The call `a.min(b)` lowers to `MathLib.min(a, b)`. A first parameter named
anything other than `self` does not opt in.

Attachment is additive and type-directed. A real field or built-in member wins
over a library attachment. If two visible libraries attach the same name to the
same receiver type, the call is ambiguous and rejects. The convention also
works through imports and inside supported library-to-library calls.

`@using(Library)` remains useful for attaching functions whose first parameter
does not use the `self` convention, and for making attachment scope explicit.

## External libraries

A supported ABI-exposed function in a static class compiles to a separate
library artifact. Contract calls use `DELEGATECALL` and require link-time address
patching.

```jeth
static class ExternalMath {
  add(a: u256, b: u256): External<u256> {
    return a + b;
  }
}

class C {
  value: u256;

  add(a: u256, b: u256): External<void> {
    this.value = ExternalMath.add(a, b);
  }
}
```

The compiler result includes library artifacts and link references. A deployment
tool must:

1. deploy each required library;
2. verify its deployed address and bytecode;
3. patch every reference in the dependent creation bytecode;
4. deploy the linked contract;
5. preserve build metadata for verification.

Because external libraries use delegatecall, their code executes in the calling
contract's storage and address context. Storage-reference library parameters are
restricted to supported paths.

## Library restrictions

Libraries cannot have ordinary contract instance state or constructors. External
library methods cannot be payable because delegatecall does not transfer a new
call value.

Library overloads, cross-library calls, attached calls, dynamic parameters, and
returns are accepted only where the compiler has a verified ABI/linking path.
