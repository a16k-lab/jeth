# Arch over-rejection #1: memory struct local from a calldata struct-array element (+ for..of)

> **Historical (design/build record).** JETH is now native-syntax only: the decorator spellings below are
> the retired legacy surface (`// use @decorators` -> JETH480, structural decorators -> JETH481). See the
> [native-spelling table](../SUPPORTED.md#legacy-decorator-removal-native-syntax-only). The described
> semantics are unchanged; only the surface syntax was replaced.

A SAFE over-rejection (JETH cleanly rejects, solc 0.8.35 accepts; never a miscompile). Close it byte-identical.
This is the FIRST of three architectural items; do ONLY this one.

## What solc accepts that JETH rejects (JETH900)
```typescript
@struct class P { a: u256; b: u256; }          // (and a DYNAMIC-field P with bytes/array fields)
@contract class C {
  @external @pure f(ps: P[]): u256 {           // ps: a calldata dynamic array of structs
    let p: P = ps[0n];                         // <-- JETH900: bind a calldata struct ELEMENT to a memory local
    return p.a + p.b;
  }
  @external @pure g(ps: P[]): u256 {
    let t: u256 = 0n;
    for (const p of ps) { t = t + p.a; }       // <-- for..of over a calldata struct array (same materialization)
    return t;
  }
}
```
solc accepts both (`P memory p = ps[0];` copies the calldata struct element into a memory image; `for (P
calldata p : ps)` / the indexed equivalent). The MANUAL index loop reading fields directly (`ps[i].a`) already
works in JETH - only BINDING the element to a memory struct LOCAL is gated.

## Why it is gated + the machinery that already exists
The localDecl handler (src/analyzer.ts ~7040-7095) already materializes a WHOLE calldata struct PARAM
(`cdDynStructValue`) into a memory struct local (copied into a fresh pointer-headed image). The gates at
analyzer.ts ~7155 / ~7211 (JETH900) fire for the sources NOT yet routed - including a calldata struct-array
ELEMENT (`ps[0n]`), which the analyzer types as a calldata struct at a runtime offset (a `cdDynArrayElem` /
nested calldata-struct ref), NOT a whole-param `cdDynStructValue`.

src/yul.ts `buildDynStructFromCalldata` (~4489) builds the POINTER-HEADED memory image a `memDynStruct` local
consumes FROM a calldata struct reference (value fields inline; a bytes/string/dyn-array field's head word = an
absolute memory pointer). It is the exact materializer needed; it just needs to accept a struct ELEMENT
reference (the calldata offset of `ps[i]`) as its source, not only a whole `cdDynStructValue` param.

## Fix
- Analyzer: recognize `let p: P = <calldata struct-array element>` (and the for..of binding, which desugars to
  an indexed `p = ps[i]`) as a SUPPORTED memory-struct-local init when `P` is a supported struct local
  (`isSupportedDynStructLocal` - the same set the whole-param path admits: value fields, bytes/string fields,
  dyn-value-array fields). Lift the JETH900 gate for this source; KEEP it for the genuinely-unsupported struct
  shapes (e.g. a nested-array-field struct that isSupportedDynStructLocal already excludes). Produce an IR that
  carries the calldata element reference so yul can materialize it.
- yul: materialize the calldata struct element to the pointer-headed memory image via
  buildDynStructFromCalldata applied to the ELEMENT's calldata offset (the cdDynArrayElem already computes the
  element offset for the existing direct-field-read path - reuse it to get the struct base, then run the same
  materializer the whole-param path uses). Bind the resulting pointer as the local (a `memDynStruct` local).
  A STATIC struct element (value-only fields) uses the existing static-aggregate copy path
  (storeStaticAggFromMem / aggToMemPtr) instead - simpler; cover it too.
- for..of over a calldata struct array: the existing for..of desugar mints an index temp and binds
  `const p = ps[i]` each iteration - route that binding through the same new materialization.

## Byte-identity (vs solc 0.8.35)
solc copies the calldata struct element into a fresh memory image (a deep copy: value fields, and a bytes/
string/array field copied to fresh memory). The observable result is identical field reads/writes on the local
and identical returndata when the local (or its fields) is returned/used. Verify: read `p.a`/`p.b`; mutate a
field of the local and confirm it does NOT alias the calldata (a memory copy); a dynamic-field struct element
(`bytes`/`u256[]` field) - copy + read the field; the for..of sum. Both a STATIC struct element and a
DYNAMIC-field struct element.

## Constraints + verification
tsc clean; full suite stays green and byte-identical (currently 275 files / 2336 tests); NEVER edit/relax an
existing test except one asserting EXACTLY the lifted JETH900 (flip to acceptance). Do NOT change any
currently-accepted program's output; do NOT introduce an acceptance solc rejects (a genuinely-unsupported
struct shape must still reject). Add test/arch-calldata-struct-local.test.ts: deploy a JETH contract + a solc
mirror, pass an ABI-encoded `P[]`, diff returndata (field reads, the for..of sum, a mutate-then-read showing
the copy doesn't alias). Use the Harness/compileSolidity conventions; integer literals need the `n` suffix.
Project rule: graphify FIRST, then read exact lines.
