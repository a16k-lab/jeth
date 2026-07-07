// Lowering: ContractIR -> a Yul object (directive §3.1-§3.4, §5 step 6).
//
// Value representation conventions (all values are 256-bit Yul words):
//   uintN   - zero-extended, value in [0, 2^N)
//   intN    - sign-extended two's complement
//   bool    - 0 or 1
//   address - zero-extended 160-bit value
//   bytesN  - left-aligned (data in the high N bytes)
// These match Solidity's in-register conventions so ABI encode/decode is a no-op
// for static value types (the word is already the 32-byte ABI slot).
//
// Arithmetic is CHECKED by default: every +,-,*,/,% lowers to a helper that
// reverts with Panic(0x11) on overflow / Panic(0x12) on division by zero,
// matching Solidity >=0.8.
import { ContractIR, FunctionIR, LibraryIR, SpecialEntryIR, Stmt, Expr, BinOp, RevertReason, EventIR, ArrIndexStep } from './ir.js';
import { keccak, toHex } from './selectors.js';
import {
  JethType,
  StructField,
  canonicalName,
  typesEqual,
  intRange,
  storageByteSize,
  storageSlotCount,
  isBytesLike,
  isDynamicType,
  isStaticType,
  isStaticValueType,
  isValueWord,
  isValueWordAggregate,
  isNestedValueArray,
  isNestedValueWordArray,
  isValueLeafArray,
  isValueWordLeafArray,
  isAggregateLeafArray,
  isStaticStructLeafArray,
  isStaticStructFixedLeafArray,
  isStaticStructAnyLeafArray,
  isDynBytesFixedLeafArray,
  isDynLeafFixedArray,
  isDynStructFixedLeafArray,
  isDynStructElemArrayField,
  isDynStructLeafArrayField,
  isDynLeafTopicArray,
  isImplicitWiden,
  arrayElemPacks,
  abiHeadWords,
  abiLeaves,
  structStorageLeaves,
} from './types.js';
import type {
  ArrayExpr,
  AccessPath,
  CalldataPlace,
  CdDynPlace,
  LValue,
  DestructureSource,
  SuccessCheck,
} from './ir.js';

export class UnsupportedError extends Error {
  /** Diagnostic code the compile driver surfaces (defaults to the generic JETH900). A lowering
   *  rejection with a first-class code (e.g. the W6A JETH465 aliasing-capture reject) sets it so
   *  the CompileError carries a specific, greppable code instead of the catch-all. */
  readonly code: string;
  constructor(message: string, code = 'JETH900') {
    super(message);
    this.name = 'UnsupportedError';
    this.code = code;
  }
}

/** Cat B: a STATIC-STRUCT memory-array element is laid out POINTER-HEADED (one absolute-pointer
 *  word per element -> a fresh per-element image), like solc's memory model for reference types,
 *  while a static VALUE leaf or static VALUE sub-array (u256[], Arr<u256,N>[]) stays INLINE. Used
 *  at every codec / construct / zero-init / write site that forks on `isStaticType(t.element)` to
 *  add the pointer-headed sub-branch for a struct element WITHOUT touching the value-leaf path.
 *  A DYNAMIC-FIELD struct (B3, isStaticType=false) is NOT matched here: it stays on the existing
 *  dynamic/else branch (already pointer-headed), so this predicate requires a STATIC struct. */
function isPointerHeadedStaticElem(e: JethType): boolean {
  if (e.kind === 'struct') return isStaticType(e);
  // Batch A: a STATIC fixed array whose leaf is a static struct (Arr<P,N>) is a REFERENCE type too, so
  // as the element of a containing array (Arr<P,N>[], Arr<Arr<P,N>,M>) it is one absolute-pointer word
  // per element -> a fresh per-element Arr<P,N> image. A static fixed array whose leaf is a VALUE type
  // (Arr<u256,N>) stays INLINE (byte-invariant): isStaticStructFixedLeafArray excludes value leaves.
  if (e.kind === 'array' && e.length !== undefined) return isStaticStructFixedLeafArray(e);
  return false;
}

/** A nested-array ELEMENT that is laid out INLINE (its value words sit in the parent image, no per-element
 *  pointer): a static VALUE type/sub-array (Arr<u256,N>) OR a FUNCREF-value aggregate (Arr<(x)=>R,N>, a
 *  value-word struct). The funcref-admitting widening of `isStaticType(e) && !isPointerHeadedStaticElem(e)`:
 *  isValueWordAggregate is the strict superset of isStaticType that also counts a funcref word, and the
 *  !isPointerHeadedStaticElem guard still routes a static STRUCT / static-struct-leaf array element to the
 *  pointer-headed branch (a value/funcref struct is inline; a struct with a reference leaf is not). Used
 *  ONLY at the nested memory codec's inline-vs-pointer element forks. */
function isInlineValueWordElem(e: JethType): boolean {
  return isValueWordAggregate(e) && !isPointerHeadedStaticElem(e);
}

/** R3: does a struct's field tree contain a dynamic ARRAY member, either directly or reachable THROUGH a
 *  nested struct field (at any depth)? A direct calldata-source encode of such a shape has no calldata
 *  array encoder (arrayFieldRef / encodeDynFieldInto throw on a 'cd' source when a nested struct field's
 *  own member is an array), so the caller must MATERIALIZE the whole calldata struct to a pointer-headed
 *  memory image first (buildDynStructFromCalldata, the SAME path a `let m: S = p` bind uses) and re-encode
 *  from a 'mem' source. Excludes a struct that only carries scalar / bytes / string leaves or nested
 *  structs of the same (those keep the direct calldata fast path). Only dynamic (length-undefined) arrays
 *  count: a FIXED value array Arr<u256,N> is a static inline leaf on the calldata path. A fixed-outer
 *  dynamic-element array (Arr<string,N>) is caught here (its outer length is fixed but it is a dynamic
 *  member the direct cd path also cannot encode). */
function structTreeHasArrayMember(struct: JethType & { kind: 'struct' }): boolean {
  return struct.fields.some((f) => {
    const t = f.type;
    if (t.kind === 'array') {
      // a dynamic array (length undefined) OR a fixed-outer array whose element is itself dynamic
      // (Arr<string,N>) is a member the direct calldata encode path cannot handle.
      return t.length === undefined || isDynamicType(t);
    }
    if (t.kind === 'struct') return structTreeHasArrayMember(t);
    return false;
  });
}

// Phase 6 external-call scoped bindings (this.ok / this.data inside a success condition). These keys
// are bound in the LowerCtx scope while a check is lowered; the leading '#' cannot collide with a
// user identifier. callOk resolves to the success-bool register; callData to the returndata pointer.
const EXT_CALL_OK_BINDING = '#extCallOk';
const EXT_CALL_DATA_BINDING = '#extCallData';

// F4 @nonReentrant: a dedicated TRANSIENT-storage slot (EIP-1153, its own address space, wiped at
// end of transaction and reverted on a failed call) holds the mutex. The slot is namespaced by a
// keccak so it cannot collide with any future transient use; its value is never observable on chain.
const REENTRANCY_TSLOT = '0xe3c13ce1a6dbca2cd747af6cfb37b5bfaa572cf58e51980e617e5acd973fa8b3'; // keccak("jeth.nonReentrant.guard.v1")
// The OpenZeppelin custom error ReentrancyGuardReentrantCall() (selector 0x3ee5aeb5), left-aligned in
// a word, so a reentrant call reverts with revert data byte-identical to OZ's transient guard.
const REENTRANCY_ERROR_WORD = '0x3ee5aeb500000000000000000000000000000000000000000000000000000000';

// OpenZeppelin 5.x ECDSA constants. HALF_ORDER == floor(secp256k1.N / 2); the high-s rejection is STRICT
// `s > HALF_ORDER` (so s == HALF_ORDER is accepted). The three custom-error selectors are left-aligned in a
// word for `mstore(0, <word>)` + revert(0, 4 [+0x20]), byte-identical to OZ's custom-error encoding.
const HALF_ORDER = '0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0';
const ECDSA_INVALID_SIGNATURE = '0xf645eedf00000000000000000000000000000000000000000000000000000000'; // ECDSAInvalidSignature()
const ECDSA_INVALID_SIGNATURE_LENGTH = '0xfce698f700000000000000000000000000000000000000000000000000000000'; // ECDSAInvalidSignatureLength(uint256)
const ECDSA_INVALID_SIGNATURE_S = '0xd78bce0c00000000000000000000000000000000000000000000000000000000'; // ECDSAInvalidSignatureS(bytes32)
// EIP-4844 KZG point-evaluation (0x0a) success-output constants (cancun-pinned).
const KZG_FIELD_ELEMENTS_PER_BLOB = '0x0000000000000000000000000000000000000000000000000000000000001000'; // 4096
const KZG_BLS_MODULUS = '0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001';

// Phase 2a proxies: the canonical EIP-1967 fixed slots (collision-resistant, the OZ ERC1967 layout).
// impl  = keccak256("eip1967.proxy.implementation") - 1; admin = keccak256("eip1967.proxy.admin") - 1.
const EIP1967_IMPL_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const EIP1967_ADMIN_SLOT = '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103';
// keccak256("Upgraded(address)") - the EIP-1967 Upgraded(address indexed implementation) topic0.
const UPGRADED_TOPIC = '0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b';
// Phase 2b transparent proxy: the only selector the admin may call (upgradeToAndCall(address,bytes)), and
// the OZ TransparentUpgradeableProxy revert when the admin calls anything else (ProxyDeniedAdminAccess()).
const UPGRADE_TO_AND_CALL_SELECTOR = '0x4f1ef286';
const PROXY_DENIED_ADMIN_ACCESS_SELECTOR = '0xd2b576ec';
// Phase 2c (UUPS): the anti-brick check selectors (byte-identical to OZ UUPSUpgradeable / ERC1967Utils).
// proxiableUUID() = the selector STATICCALL'd on the new impl; the two revert errors on a failed/mismatched
// anti-brick check. All keccak256(sig)[0:4], verified via functionSelector.
const PROXIABLE_UUID_SELECTOR = '0x52d1902d';
const ERC1967_INVALID_IMPLEMENTATION_SELECTOR = '0x4c9c8ce3'; // ERC1967InvalidImplementation(address)
const UUPS_UNSUPPORTED_PROXIABLE_UUID_SELECTOR = '0xaa1d49a4'; // UUPSUnsupportedProxiableUUID(bytes32)
// Phase 2d (BEACON): the EIP-1967 beacon slot (keccak256("eip1967.proxy.beacon") - 1), the beacon's
// implementation() selector STATICCALL'd on every proxied call, and the OZ BeaconUpgraded(address indexed)
// topic0 (emitted by a beacon PROXY when its beacon slot is set, distinct from Upgraded). The beacon
// CONTRACT itself emits Upgraded(address indexed) (same UPGRADED_TOPIC as ERC1967). All verified via keccak.
const EIP1967_BEACON_SLOT = '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50';
const IMPLEMENTATION_SELECTOR = '0x5c60da1b'; // implementation()
const BEACON_UPGRADED_TOPIC = '0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e'; // BeaconUpgraded(address)
// Phase 2d (BEACON contract): the OZ Ownable owner-gate revert (OwnableUnauthorizedAccount(address)). The
// UpgradeableBeacon stores owner at slot 0 (Ownable._owner) and implementation at slot 1.
const OWNABLE_UNAUTHORIZED_SELECTOR = '0x118cdaa7'; // OwnableUnauthorizedAccount(address)

// Phase 3 (DIAMOND): keccak256("OwnershipTransferred(address,address)") - the ERC-173 topic0 (both args
// indexed); emitted by diamondInit (raw Yul) and by the synthesized transferOwnership (normal emit path).
const OWNERSHIP_TRANSFERRED_TOPIC = '0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0';
// The four ERC-165 interface ids diamondInit registers: IERC165, IDiamondCut (diamondCut.selector),
// IDiamondLoupe (XOR of the 4 loupe selectors), IERC173. Each set true in supportedInterfaces.
const DIAMOND_ERC165_IDS = ['0x01ffc9a7', '0x1f931c1c', '0x48e2b093', '0x7f5828d0'];
// The FIVE ERC-165 interface ids the solidstate v0.0.61 SolidStateDiamond constructor registers:
// IDiamondFallback (XOR of getFallbackAddress/setFallbackAddress), IERC2535DiamondCut, IERC2535DiamondLoupe,
// IERC165, IERC173.
const SOLIDSTATE_ERC165_IDS = ['0xbd02b73c', '0x1f931c1c', '0x48e2b093', '0x01ffc9a7', '0x7f5828d0'];

/** ABI head-word count of a struct's tuple HEAD (spec section 3.0): each field
 *  contributes its inline static words if static, or exactly ONE offset word if
 *  dynamic (string/bytes/dynamic-array/nested-dynamic-struct). This differs from
 *  abiHeadWords, which expands a (sub)struct into all of its leaf words even when
 *  that struct is dynamic. Used for tuple-head bounds checks and field offsets. */
function tupleHeadWords(t: JethType & { kind: 'struct' }): number {
  return t.fields.reduce((n, f) => n + (isDynamicType(f.type) ? 1 : abiHeadWords(f.type)), 0);
}

/** Bytes of a dynamic element/field's HEAD that must be readable at its calldata
 *  pointer before decoding: a struct tuple needs its WHOLE head (headWords*32); any
 *  other dynamic type (bytes/string/array) needs only its first length/offset word. */
function cdElemHeadBytes(t: JethType): number {
  return t.kind === 'struct' ? tupleHeadWords(t) * 32 : 32;
}

function toWord(v: bigint): string {
  let x = v % (1n << 256n);
  if (x < 0n) x += 1n << 256n;
  return '0x' + x.toString(16);
}
function uintMaxHex(bits: number): string {
  return '0x' + ((1n << BigInt(bits)) - 1n).toString(16);
}
/** Mask of the low (32 - size) bytes: the padding region of a left-aligned bytesN. */
function bytesNLowMaskHex(size: number): string {
  return '0x' + ((1n << BigInt((32 - size) * 8)) - 1n).toString(16);
}
/** Mask of the high `size` bytes: the data region of a left-aligned bytesN (used to keep the
 *  padding region zero after `~` / `>>` whose word-level op would otherwise dirty the low bytes). */
function bytesNHighMaskHex(size: number): string {
  return '0x' + (((1n << BigInt(size * 8)) - 1n) << BigInt((32 - size) * 8)).toString(16);
}
/** Big-endian 32-byte word from `bytes` at `start`, right zero-padded (matches
 *  Solidity's left-aligned string/bytes tail words). */
function wordFromBytes(bytes: Uint8Array, start: number): string {
  let hex = '';
  for (let i = 0; i < 32; i++) {
    const b = start + i < bytes.length ? bytes[start + i]! : 0;
    hex += b.toString(16).padStart(2, '0');
  }
  return '0x' + hex;
}

export class YulEmitter {
  private helpers = new Map<string, string>();
  private tmp = 0;
  private nameCounter = 0; // per-function unique local-name counter
  private funcs = new Map<string, FunctionIR>(); // contract functions by name (internal-call targets)
  private contract?: ContractIR; // the contract being emitted (for the diamond storage base/slots)
  // W5D-1: per-constructor-emission registry of OUTLINED ctor units. A ctorOutlineBind lowers its body
  // as a creation-block Yul function (def collected in ctorOutlineDefs, hoisted next to
  // jeth_constructor) and records the call shape here; each ctorOutlineCall reads it. Reset per
  // emitConstructor; the nodes never appear outside a constructor body.
  private ctorOutlines = new Map<number, { fnName: string; argRegs: string[]; immNames: string[] }>();
  private ctorOutlineDefs: string[] = [];

  emit(contract: ContractIR): string {
    this.contract = contract;
    for (const f of contract.functions) this.funcs.set(f.key, f); // by unique key (overload-safe)
    const runtime = this.emitRuntime(contract);
    const creation = this.emitCreation(contract);
    return `object "${contract.name}" {
  code {
${indent(creation, 4)}
  }
  object "${contract.name}_runtime" {
    code {
${indent(runtime, 6)}
    }
  }
}
`;
  }

  /** Phase B: emit ONE external (delegatecall) library as its own top-level deployable Yul object.
   *  The runtime is a selector dispatcher over the library's @external functions (same structure as a
   *  contract runtime via emitRuntime) plus its object-local internal userfn_s. The creation copies the
   *  runtime out and returns it (non-payable at deploy, like a constructorless contract). A library has
   *  no state/constructor/immutables/special entries, so a synthetic ContractIR carries empty ones.
   *  YulEmitter state (helpers/funcs/counters) is saved + isolated so a helper a library body pulls in
   *  is defined INSIDE the library's runtime scope, not leaked into the contract object. */
  emitLibraryObject(lib: LibraryIR): string {
    const savedFuncs = this.funcs;
    const savedHelpers = this.helpers;
    const savedTmp = this.tmp;
    this.funcs = new Map<string, FunctionIR>();
    this.helpers = new Map<string, string>();
    const fns = [...lib.external, ...lib.internal];
    for (const f of fns) this.funcs.set(f.key, f);
    const synthetic: ContractIR = {
      name: lib.name,
      stateVars: [],
      functions: fns,
      errors: [],
      events: [],
      slotCount: 0,
      immutables: [],
    };
    const runtime = this.emitRuntime(synthetic);
    // Creation: a library deploy takes no value (non-payable) and no args; copy the runtime out + return.
    const creationLines = [
      'if callvalue() { revert(0, 0) }',
      `datacopy(0, dataoffset("${lib.name}_runtime"), datasize("${lib.name}_runtime"))`,
      `return(0, datasize("${lib.name}_runtime"))`,
    ];
    const creation = creationLines.join('\n');
    this.funcs = savedFuncs;
    this.helpers = savedHelpers;
    this.tmp = savedTmp;
    return `object "${lib.name}" {
  code {
${indent(creation, 4)}
  }
  object "${lib.name}_runtime" {
    code {
${indent(runtime, 6)}
    }
  }
}
`;
  }

  // ---- creation / constructor code ----------------------------------------

  private emitCreation(contract: ContractIR): string {
    // Phase 2d (BEACON contract): a `@beacon class` has a FULLY-synthesized creation, byte-identical to the
    // OZ UpgradeableBeacon 5.x constructor (Ownable(msg.sender) + _setImplementation(impl)): non-payable;
    // owner = msg.sender at slot 0; decode the single appended `impl` address arg; require(isContract(impl));
    // store impl at slot 1; emit Upgraded(indexed impl); then copy out + return the runtime. The user's
    // `constructor(impl: address) {}` body is empty (enforced by the analyzer) - only its single param
    // defines the appended ABI arg, so we ignore contract.ctor.body entirely here.
    if (contract.isBeacon) return this.emitBeaconCreation(contract);
    const lines: string[] = [];
    // A constructorless contract is non-payable at creation: reject any deploy value, exactly like
    // solc (which always emits this guard at the start of creation unless the constructor is explicitly
    // @payable). When there IS a constructor, emitConstructor emits the guard itself (unless @payable).
    if (!contract.ctor) lines.push('if callvalue() { revert(0, 0) }');
    // Write non-default state initializers. All are compile-time constants, so we
    // pack each affected slot into a single word and emit one sstore per slot.
    const slotWords = new Map<bigint, bigint>();
    for (const v of contract.stateVars) {
      if (v.initialValue === undefined) continue;
      const size = storageByteSize(v.type);
      let raw: bigint;
      if (typeof v.initialValue === 'boolean') raw = v.initialValue ? 1n : 0n;
      else if (v.type.kind === 'bytesN')
        // foldConstant returns a bytesN in its LEFT-aligned register form (the value in the high N bytes
        // of a word); storage holds it RIGHT-aligned within the field's `size` bytes (exactly what
        // storeState does via shr((32-size)*8)), so right-align before packing. Masking the left-aligned
        // form to the low `size` bytes would zero it (the silent bytesN state-initializer miscompile).
        raw = (v.initialValue >> BigInt((32 - v.type.size) * 8)) & ((1n << BigInt(size * 8)) - 1n);
      else raw = v.initialValue & ((1n << BigInt(size * 8)) - 1n);
      const shifted = raw << BigInt(v.offset * 8);
      slotWords.set(v.slot, (slotWords.get(v.slot) ?? 0n) | shifted);
    }
    for (const [slot, word] of [...slotWords.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))) {
      lines.push(`sstore(${slot}, ${toWord(word)})`);
    }
    // Phase 5: run the constructor body (if any) AFTER the constant-field initializers and BEFORE
    // copying out + returning the runtime code. The ctor's helper definitions are appended at the
    // end of THIS creation block (a separate Yul scope from the runtime object).
    let ctorHelpers: string[] = [];
    const staged = new Map<string, string>(); // @immutable name -> the Yul var holding its baked value
    if (contract.ctor) {
      const c = this.emitConstructor(contract);
      lines.push(...c.lines);
      ctorHelpers = c.helpers;
      for (const [k, v] of c.staged) staged.set(k, v);
    }
    lines.push(`datacopy(0, dataoffset("${contract.name}_runtime"), datasize("${contract.name}_runtime"))`);
    // Bake every @immutable into the (in-memory copy of the) runtime code via setimmutable. The
    // value is the staged shadow when the ctor assigned it, else 0 (solc: a never-assigned immutable
    // reads as 0). setimmutable requires a matching loadimmutable in the runtime, which only exists
    // when the immutable is actually read - but an unread immutable's setimmutable is a harmless no-op.
    for (const im of contract.immutables) {
      lines.push(`setimmutable(0, "${im.name}", ${staged.get(im.name) ?? '0'})`);
    }
    lines.push(`return(0, datasize("${contract.name}_runtime"))`);
    for (const def of ctorHelpers) {
      lines.push('');
      lines.push(def);
    }
    return lines.join('\n');
  }

  /** Phase 5: emit the constructor prologue (non-payable callvalue guard + decode the appended
   *  ABI-encoded args from MEMORY) and a synthesized `jeth_constructor(...)` Yul function for the
   *  body, then call it. Returns the inline creation lines and the function/helper definitions to
   *  place at the end of the creation block. The body runs inside a Yul function so a `return;`
   *  becomes `leave` (exit the ctor, then deploy) rather than a raw EVM return (empty code). */
  private emitConstructor(contract: ContractIR): { lines: string[]; helpers: string[]; staged: Map<string, string> } {
    const ctor = contract.ctor!;
    this.nameCounter = 0;
    // W5D-1: fresh outlined-unit registry for THIS constructor emission.
    this.ctorOutlines = new Map();
    this.ctorOutlineDefs = [];
    const lines: string[] = [];
    // Non-payable constructor: reject any value sent at deploy (solc emits this guard).
    if (!ctor.payable) lines.push('if callvalue() { revert(0, 0) }');

    // Each @immutable is a RETURN VARIABLE of jeth_constructor: zero-initialized (matching a
    // never-assigned immutable), last-write-wins, and readable after the function returns (`leave`).
    // The body writes/reads them via ctx.immStaged (the inner ret-var names); the OUTER capture vars
    // (distinct names, to avoid Yul shadowing) feed setimmutable in emitCreation.
    const immStaged = new Map<string, string>(); // immutable name -> inner ret var
    const innerRets: string[] = [];
    const outerRets: string[] = [];
    const staged = new Map<string, string>(); // immutable name -> outer capture var
    for (const im of contract.immutables) {
      const inner = this.freshLocal(`imm_${im.name}`);
      const outer = this.fresh();
      immStaged.set(im.name, inner);
      innerRets.push(inner);
      outerRets.push(outer);
      staged.set(im.name, outer);
    }

    const ctx: LowerCtx = {
      scopes: [new Map()],
      returnType: { kind: 'void' } as JethType,
      dynParams: new Map(),
      cdArrays: new Map(),
      cdAggregates: new Map(),
      cdDynStructs: new Map(),
      cdParamHead: new Map(),
      fnMode: { retVar: null }, // a bare `return;` in the ctor body -> leave
      immStaged,
    };

    // Determine which @immutables are READ by a function reachable from the constructor (a loadimmutable
    // in the creation block would collide with the ctor's setimmutable of the same immutable: solc's
    // legacy assembler rejects push+assign of one immutable in one subroutine). Each such immutable gets a
    // reserved creation-block MEMORY cell holding its staged value; the helper copy reads it via mload and
    // the staged write mirrors into it. The cells occupy a fixed prefix [0x80, 0x80 + 32*nShadow); ARGS and
    // the initial free pointer start ABOVE the prefix so neither the args blob nor body allocations clobber
    // them. (A direct ctor-body read uses the staged ret-var, not loadimmutable, so it never needs a cell.)
    const ctorReachable = this.ctorReachableFns(ctor.body);
    const immReadByHelper = new Set<string>();
    for (const fn of ctorReachable) {
      for (const nm of this.collectImmutableReads(fn.body)) immReadByHelper.add(nm);
      if (fn.modifierWrap) for (const nm of this.collectImmutableReads(fn.modifierWrap)) immReadByHelper.add(nm);
    }
    const ctorImmShadow = new Map<string, string>(); // @immutable name -> reserved memory cell address
    let shadowBytes = 0;
    for (const im of contract.immutables) {
      if (immReadByHelper.has(im.name)) {
        ctorImmShadow.set(im.name, String(0x80 + shadowBytes));
        shadowBytes += 32;
      }
    }
    if (ctorImmShadow.size > 0) ctx.ctorImmShadow = ctorImmShadow;
    const MEM0 = 0x80 + shadowBytes; // memory base above the immutable-shadow prefix

    // Decode the constructor args (ABI-encoded, appended after the init code). They begin at code
    // offset datasize("C") (the init-code size) and run to codesize(). Copy them into memory at MEM0
    // and decode from MEMORY. A STATIC param occupies abiHeadWords inline words in the head; a DYNAMIC
    // param (T[]/bytes/string/dynamic struct/Arr<dyn,N>) occupies ONE head OFFSET word (its tail lives
    // later in the blob), exactly as solc lays it out (matching the calldata + abi.decode disciplines).
    // solc reverts EMPTY when the args region is shorter than the static head, and ignores trailing bytes.
    const ARGS = MEM0;
    // a static aggregate occupies all its leaf words inline; a dynamic param occupies one offset word.
    const paramHeadWords = (t: JethType): number => (isDynamicType(t) ? 1 : abiHeadWords(t));
    const headWords = ctor.params.reduce((n, p) => n + paramHeadWords(p.type), 0);
    const headBytes = headWords * 32;
    // Are any params aggregate/dynamic (i.e. do we need the WHOLE args blob, with tails, in memory)?
    const anyAggregate = ctor.params.some((p) => !isStaticValueType(p.type));
    const blobEnd = this.fresh(); // absolute memory end of the args blob (for abiDecFromMem bounds)
    if (headWords > 0) {
      lines.push(`let _argsLen := sub(codesize(), datasize("${contract.name}"))`);
      lines.push(`if lt(_argsLen, ${headBytes}) { revert(0, 0) }`);
      if (anyAggregate) {
        // copy the ENTIRE args region (head + every dynamic tail) so a tail offset resolves in memory.
        lines.push(`codecopy(${ARGS}, datasize("${contract.name}"), _argsLen)`);
        lines.push(`let ${blobEnd} := add(${ARGS}, _argsLen)`);
        // free pointer past the whole copied blob (word-rounded) so materialized images never clobber it.
        lines.push(`mstore(0x40, add(${ARGS}, and(add(_argsLen, 0x1f), not(0x1f))))`);
      } else {
        lines.push(`codecopy(${ARGS}, datasize("${contract.name}"), ${headBytes})`);
        lines.push(`let ${blobEnd} := add(${ARGS}, _argsLen)`);
        // free-memory pointer past the decoded args, so a body allocation cannot clobber them.
        lines.push(`mstore(0x40, ${ARGS + headBytes})`);
      }
    } else {
      lines.push(`let ${blobEnd} := ${ARGS}`); // no params: unused, but keep the binding well-formed
      lines.push(`mstore(0x40, ${MEM0})`); // init the free-memory pointer above the immutable-shadow prefix
    }
    // Zero-init each reserved immutable-shadow cell so a helper read BEFORE the immutable is assigned
    // sees 0 (solc: a not-yet-assigned immutable reads as 0 during construction). The cells sit below the
    // free pointer (the [0x80, MEM0) prefix), so allocations never overwrite them.
    for (const cell of ctorImmShadow.values()) lines.push(`mstore(${cell}, 0)`);
    // Open the FRESH helpers window NOW (before decoding), so any helper the aggregate-param decode
    // pulls in (panic/alloc/...) is defined in THIS creation block, not the runtime object. The window
    // also covers the body lowering + the ctor-reachable internal-function emission below.
    const savedHelpers = this.helpers;
    this.helpers = new Map();
    const formals: string[] = []; // the synthesized function's parameter names (v_<name>_N)
    const decoded: string[] = []; // the outer decode locals (_tN) passed at the call site
    let cursorWords = 0;
    for (const p of ctor.params) {
      const formal = this.freshLocal(p.name);
      this.ctxDeclare(ctx, p.name, formal);
      formals.push(formal);
      const head = `${ARGS + cursorWords * 32}`;
      cursorWords += paramHeadWords(p.type);
      if (isStaticValueType(p.type)) {
        // a value param: one validated head word, passed by value (existing path).
        const dec = this.fresh();
        lines.push(`let ${dec} := mload(${head})`);
        const guard = this.validateInput(p.type, dec);
        if (guard) lines.push(guard);
        decoded.push(dec);
      } else if (p.type.kind === 'array' && isStaticStructFixedLeafArray(p.type)) {
        // Batch A: a STATIC fixed-outer static-struct array (Arr<P,N>, Arr<Arr<P,N>,M>) is STATIC but
        // POINTER-HEADED in memory (N absolute-pointer words -> fresh per-element images). It MUST be routed
        // through abiDecFromMemToImage, which self-manages 0x40 (claims the N-word table BEFORE the per-element
        // images alloc) and returns the table pointer. The abiDecFromMem twin below would write the table into
        // `ptr := mload(0x40)` and then the FIRST per-element image (also allocated from mload(0x40)) clobbers
        // it, decoding garbage (raw creation-memory pointers) - the P0-11 miscompile. This mirrors
        // lowerAbiDecode's static-component Batch-A reroute (the runtime abi.decode path already does this).
        decoded.push(this.abiDecFromMemToImage(p.type, head, blobEnd, lines));
      } else if (!isDynamicType(p.type)) {
        // a STATIC aggregate (struct / Arr<T,N> of static VALUE leaves): materialize the inline head words
        // into a fresh memory image via the abi.decode-from-memory codec; pass the image pointer.
        const ptr = this.fresh();
        lines.push(`let ${ptr} := mload(0x40)`);
        const sz = this.abiDecFromMem(p.type, head, ptr, blobEnd, lines);
        lines.push(`mstore(0x40, add(${ptr}, ${sz}))`);
        decoded.push(ptr);
      } else {
        // a DYNAMIC param: the head word is an offset relative to the blob start (ARGS). Bound it,
        // then decode the tail into a fresh image (byte-identical to solc's memory-decode revert
        // semantics, which abiDecFromMem encodes). The image pointer is the param's memory reference.
        const so = this.fresh();
        lines.push(`let ${so} := mload(${head})`);
        lines.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        lines.push(`let ${se} := add(${ARGS}, ${so})`);
        lines.push(`if gt(add(${se}, ${cdElemHeadBytes(p.type)}), ${blobEnd}) { revert(0, 0) }`);
        if (p.type.kind === 'struct') {
          // a DYNAMIC-field struct param: build the POINTER-HEADED image a memDynStruct local reads
          // (the abiDecFromMem standard-ABI image uses relative tail offsets, which memDynField cannot
          // consume). The pointer is the param's memory reference.
          decoded.push(this.buildDynStructFromMemBlob(p.type, se, blobEnd, lines));
        } else {
          const ptr = this.fresh();
          lines.push(`let ${ptr} := mload(0x40)`);
          const sz = this.abiDecFromMem(p.type, se, ptr, blobEnd, lines);
          lines.push(`mstore(0x40, add(${ptr}, ${sz}))`);
          decoded.push(ptr);
        }
      }
    }

    // Lower the body in the same helpers window (any helper it pulls in lands in THIS creation block,
    // a separate Yul scope from the runtime object). The internal/private functions the ctor calls
    // (JETH303) live as userfn_<key> in the RUNTIME object only, so duplicate the transitively-reachable
    // ones into THIS creation block too (emitted inside the same window, so any helper THEY pull in also
    // lands here). Each emitted function resets the nameCounter, but the ctor's own fresh names are
    // already materialized above, so the jeth_constructor signature stays stable.
    const body: string[] = [];
    for (const s of ctor.body) for (const l of this.lowerStmt(s, ctx)) body.push(l);
    // Emit each transitively-reachable internal callee as a userfn_ in this creation block. Pass the
    // immutable-shadow map (when non-empty) so a helper's @immutable read lowers to mload(cell) instead
    // of loadimmutable, avoiding the same-subroutine setimmutable+loadimmutable collision.
    const ctorFnDefs: string[] = [];
    const shadowArg = ctorImmShadow.size > 0 ? ctorImmShadow : undefined;
    for (const fn of ctorReachable) ctorFnDefs.push(this.emitInternalFunction(fn, shadowArg));
    const helperDefs = [...this.helpers.values()];
    this.helpers = savedHelpers;

    const retDecl = innerRets.length ? ` -> ${innerRets.join(', ')}` : '';
    const sig = `function jeth_constructor(${formals.join(', ')})${retDecl}`;
    const ctorFn = `${sig} {\n${body.map((l) => '  ' + l).join('\n')}${body.length ? '\n' : ''}}`;
    lines.push(
      innerRets.length
        ? `let ${outerRets.join(', ')} := jeth_constructor(${decoded.join(', ')})`
        : `jeth_constructor(${decoded.join(', ')})`,
    );
    // W5D-1: the outlined ctor units (collected while lowering the body above) are creation-block
    // functions, hoisted next to jeth_constructor (Yul function definitions are order-independent).
    return { lines, helpers: [ctorFn, ...this.ctorOutlineDefs, ...ctorFnDefs, ...helperDefs], staged };
  }

  /** JETH303: collect the contract internal/private functions TRANSITIVELY reachable from the
   *  constructor body, so they can be duplicated into the creation object (where the ctor's calls
   *  resolve). Walks the IR tree for every internal-call site (`{kind:'call'|'callStmt', fn:<key>}`),
   *  then takes the transitive closure over each callee's own body via this.funcs (keyed by `key`).
   *  A function emitted with a modifierWrap is keyed the same (`internallyCalled` userfn_<key>), so the
   *  key set is sufficient. Returns the unique FunctionIRs in a stable (insertion) order. */
  private ctorReachableFns(body: Stmt[]): FunctionIR[] {
    const seen = new Set<string>();
    const order: FunctionIR[] = [];
    const visitKey = (key: string): void => {
      if (seen.has(key)) return;
      seen.add(key);
      const fn = this.funcs.get(key);
      if (!fn) return; // not a contract function (e.g. an external/library entry has no userfn here)
      order.push(fn);
      // recurse into the callee body (and its modifierWrap, if any) for transitive callees.
      for (const k of this.collectCallKeys(fn.body)) visitKey(k);
      if (fn.modifierWrap) for (const k of this.collectCallKeys(fn.modifierWrap)) visitKey(k);
    };
    for (const k of this.collectCallKeys(body)) visitKey(k);
    return order;
  }

  /** Collect the names of every @immutable READ (an `immutableRead` IR node, i.e. a runtime
   *  loadimmutable read) anywhere in the given subtrees. Used to decide which immutables need a
   *  staged-value memory shadow in the creation block: a helper reachable from the constructor that
   *  reads an immutable would emit loadimmutable in the SAME assembly subroutine as the ctor's
   *  setimmutable, which solc's legacy assembler rejects. The shadow lets the helper copy read the
   *  staged value from memory instead. (A direct ctor-body read is an `immutableStagedRead`, not an
   *  `immutableRead`, so it is NOT collected here - the direct-read case never needs the shadow.) */
  private collectImmutableReads(root: unknown): Set<string> {
    const names = new Set<string>();
    const walk = (n: unknown): void => {
      if (n === null || typeof n !== 'object') return;
      if (Array.isArray(n)) {
        for (const c of n) walk(c);
        return;
      }
      const o = n as Record<string, unknown>;
      if (o.kind === 'immutableRead' && typeof o.name === 'string') names.add(o.name);
      for (const v of Object.values(o)) walk(v);
    };
    walk(root);
    return names;
  }

  /** Structurally walk an IR subtree collecting the `fn` key of every internal-call node
   *  (`kind === 'call'` an Expr/tuple-call, or `kind === 'callStmt'` a statement call). A generic
   *  walk (over array/object children) is robust to the full Stmt/Expr union without enumerating it. */
  private collectCallKeys(root: unknown): string[] {
    const keys: string[] = [];
    const walk = (n: unknown): void => {
      if (n === null || typeof n !== 'object') return;
      if (Array.isArray(n)) {
        for (const c of n) walk(c);
        return;
      }
      const o = n as Record<string, unknown>;
      if ((o.kind === 'call' || o.kind === 'callStmt') && typeof o.fn === 'string') keys.push(o.fn);
      // A CALL THROUGH a function pointer reaches, via its dispatcher, EVERY address-taken function whose
      // signature matches the pointer type. Those userfn_ targets must be duplicated into the creation
      // object when a constructor calls through a pointer (else the dispatcher references an undefined
      // userfn_). Include each matching target key so the ctor-reachability closure pulls them in.
      if (o.kind === 'funcRefCall' && o.sig && typeof o.sig === 'object') {
        const sig = o.sig as JethType;
        for (const [key, fn] of this.funcs) {
          if (fn.returnTypes) continue;
          const fsig: JethType = {
            kind: 'funcref',
            params: fn.params.map((p) => p.type),
            ret: fn.returnType.kind === 'void' ? undefined : fn.returnType,
          };
          if ((this.contract?.funcRefIds?.has(key) ?? false) && typesEqual(fsig, sig)) keys.push(key);
        }
      }
      for (const v of Object.values(o)) walk(v);
    };
    walk(root);
    return keys;
  }

  /** Phase 2d (BEACON contract): the fully-synthesized creation code for a `@beacon class`, byte-identical
   *  to the OZ UpgradeableBeacon 5.x constructor: non-payable; owner = msg.sender (slot 0, Ownable._owner);
   *  decode the single appended `impl` address arg; require(isContract(impl)); store impl at slot 1; emit
   *  Upgraded(indexed impl); copy out + return the runtime. */
  private emitBeaconCreation(contract: ContractIR): string {
    const MASK = '0xffffffffffffffffffffffffffffffffffffffff';
    const lines: string[] = [];
    // non-payable constructor (OZ UpgradeableBeacon's is non-payable).
    lines.push('if callvalue() { revert(0, 0) }');
    // owner = msg.sender at slot 0 (OZ Ownable constructor: _transferOwnership(initialOwner=msg.sender)).
    lines.push('sstore(0, caller())');
    // decode the single appended `impl` address arg (one ABI head word at code offset datasize("C")).
    lines.push(`let _argsLen := sub(codesize(), datasize("${contract.name}"))`);
    lines.push('if lt(_argsLen, 0x20) { revert(0, 0) }');
    lines.push('mstore(0x40, 0x80) // init free memory pointer');
    lines.push(`codecopy(0x80, datasize("${contract.name}"), 0x20)`);
    // a dirty high-96-bit word reverts empty (solc's address ABI decode of the ctor arg).
    lines.push('if shr(160, mload(0x80)) { revert(0, 0) }');
    lines.push(`let _impl := and(mload(0x80), ${MASK})`);
    // require(isContract(impl)) -> a clean empty revert on a non-contract (degenerate failure path).
    lines.push('if iszero(extcodesize(_impl)) { revert(0, 0) }');
    lines.push('sstore(1, _impl)');
    // emit Upgraded(address indexed implementation): an indexed-only event, log2 over no data.
    lines.push(`log2(0, 0, ${UPGRADED_TOPIC}, _impl)`);
    lines.push(`datacopy(0, dataoffset("${contract.name}_runtime"), datasize("${contract.name}_runtime"))`);
    lines.push(`return(0, datasize("${contract.name}_runtime"))`);
    return lines.join('\n');
  }

  // ---- runtime / dispatcher ------------------------------------------------

  private emitRuntime(contract: ContractIR): string {
    const lines: string[] = [];
    lines.push('mstore(0x40, 0x80) // init free memory pointer');

    const external = contract.functions.filter((f) => f.visibility === 'external');
    const hasSpecial = !!(contract.receive || contract.fallback);
    if (contract.isProxy) {
      // Phase 2b: a transparent proxy routes the synthesized fallback by CALLER (byte-identical to OZ
      // TransparentUpgradeableProxy 5.x). caller()==admin -> the call MUST be upgradeToAndCall(address,bytes)
      // (else revert ProxyDeniedAdminAccess()); the admin upgrade runs IN the proxy and returns empty.
      // caller()!=admin -> fall through to the plain delegate fallback (EVEN an upgradeToAndCall selector -
      // a non-admin always delegates, defeating the proxy/impl selector clash). A transparent proxy has no
      // @external functions of its own (the analyzer gates them), so there is no selector switch here.
      if (contract.proxyVariant === 'transparent') {
        const admin = '_admin';
        lines.push(`let ${admin} := and(sload(${EIP1967_ADMIN_SLOT}), 0xffffffffffffffffffffffffffffffffffffffff)`);
        lines.push(`if eq(caller(), ${admin}) {`);
        // msg.sig must be upgradeToAndCall(address,bytes); a too-short calldata can't be it either. OZ
        // compares the 4-byte selector; we shift the first word right by 224. (calldatasize()<4 -> sig 0.)
        lines.push(`  if iszero(eq(shr(224, calldataload(0)), ${UPGRADE_TO_AND_CALL_SELECTOR})) {`);
        // ProxyDeniedAdminAccess(): store the 4-byte selector left-aligned and revert it. (The deny path
        // reason is OZ-identical; the success path is what we primarily byte-match.)
        lines.push(
          `    mstore(0, ${PROXY_DENIED_ADMIN_ACCESS_SELECTOR}00000000000000000000000000000000000000000000000000000000)`,
        );
        lines.push('    revert(0, 4)');
        lines.push('  }');
        for (const l of this.emitTransparentAdminUpgrade()) lines.push('  ' + l);
        lines.push('  return(0, 0)');
        lines.push('}');
      } else if (contract.proxyVariant === 'beacon') {
        // Phase 2d (beacon proxy, byte-identical to OZ BeaconProxy 5.x): the impl is NOT a fixed slot. On
        // EVERY call, read the beacon from the EIP-1967 BEACON slot, STATICCALL beacon.implementation()
        // (selector 0x5c60da1b) for the CURRENT impl, then the standard delegate tail. A failed staticcall
        // or a short return reverts (the beacon must be a live contract returning an address). This is the
        // upgrade-all-at-once property: the proxy holds no impl of its own, the beacon dictates it.
        lines.push(`let _beacon := and(sload(${EIP1967_BEACON_SLOT}), 0xffffffffffffffffffffffffffffffffffffffff)`);
        // implementation() takes no args: store the 4-byte selector left-aligned in word 0, staticcall it.
        lines.push(`mstore(0, ${IMPLEMENTATION_SELECTOR}00000000000000000000000000000000000000000000000000000000)`);
        lines.push('let _sok := staticcall(gas(), _beacon, 0, 4, 0, 0x20)');
        // a failed staticcall or a return shorter than a word -> revert (degenerate; the success path bytes
        // are what we byte-match; OZ's BeaconProxy bubbles the staticcall failure / decodes a 32-byte word).
        lines.push('if or(iszero(_sok), lt(returndatasize(), 0x20)) { revert(0, 0) }');
        lines.push('let _impl := and(mload(0), 0xffffffffffffffffffffffffffffffffffffffff)');
        lines.push('calldatacopy(0, 0, calldatasize())');
        lines.push('let _ok := delegatecall(gas(), _impl, 0, calldatasize(), 0, 0)');
        lines.push('returndatacopy(0, 0, returndatasize())');
        lines.push('switch _ok');
        lines.push('case 0 { revert(0, returndatasize()) }');
        lines.push('default { return(0, returndatasize()) }');
        return lines.join('\n');
      } else if (external.length > 0) {
        // Phase 2a (plain proxy): dispatch the proxy's OWN @external functions (e.g. the user's admin-gated
        // upgrade entry) with an EMPTY default, then fall through to the delegate fallback below.
        lines.push('if iszero(lt(calldatasize(), 4)) {');
        lines.push('  let selector := shr(224, calldataload(0))');
        lines.push('  switch selector');
        for (const fn of external) {
          lines.push(`  case 0x${fn.selector} { // ${fn.signature}`);
          for (const l of this.emitDispatchCase(fn)) lines.push('    ' + l);
          lines.push('  }');
        }
        lines.push('  default {}');
        lines.push('}');
      }
      // The canonical EIP-1967 delegate fallback (the non-admin path for a transparent proxy). impl is read
      // from the fixed slot, masked to 160 bits, then ALL calldata is delegatecall'd to it.
      lines.push(`let _impl := and(sload(${EIP1967_IMPL_SLOT}), 0xffffffffffffffffffffffffffffffffffffffff)`);
      lines.push('calldatacopy(0, 0, calldatasize())');
      lines.push('let _ok := delegatecall(gas(), _impl, 0, calldatasize(), 0, 0)');
      lines.push('returndatacopy(0, 0, returndatasize())');
      lines.push('switch _ok');
      lines.push('case 0 { revert(0, returndatasize()) }');
      lines.push('default { return(0, returndatasize()) }');
    } else if (contract.isDiamond) {
      // Phase 3 DIAMOND: the diamond's OWN @external functions (diamondCut / the 4 loupe fns / owner /
      // transferOwnership / supportsInterface - the "immutable functions" of EIP-2535) dispatch first in
      // a normal selector switch with an EMPTY default; an unmatched selector FALLS THROUGH to the router.
      if (external.length > 0) {
        lines.push('if iszero(lt(calldatasize(), 4)) {');
        lines.push('  let selector := shr(224, calldataload(0))');
        lines.push('  switch selector');
        for (const fn of external) {
          lines.push(`  case 0x${fn.selector} { // ${fn.signature}`);
          for (const l of this.emitDispatchCase(fn)) lines.push('    ' + l);
          lines.push('  }');
        }
        lines.push('  default {}');
        lines.push('}');
      }
      // The router: look up the facet address for msg.sig from the facets mapping at the diamond-storage
      // base, then delegatecall the facet with all calldata and return-or-bubble. msg.sig is shr(224)
      // (right-aligned); the bytes4 mapping key is stored LEFT-aligned, so shl(224) it for the keccak.
      // Byte-identical to mudgen's Diamond.sol fallback.
      //   array  (diamond-1/3): value = mapping(bytes4 => {address facet; uint96 pos}); the address is the
      //                         LOW 160 bits of the single packed slot -> and(value, ADDR_MASK).
      //   packed (diamond-2):   value = mapping(bytes4 => bytes32) where the facet address is the HIGH 20
      //                         bytes (address | uint16 position) -> shr(96, value) = address(bytes20(value)).
      const sel2 = String(contract.diamondSel2FacetSlot ?? contract.diamondStorageBase ?? 0n);
      lines.push('let _sig := shr(224, calldataload(0))');
      lines.push('mstore(0x00, shl(224, _sig))');
      lines.push(`mstore(0x20, ${sel2})`);
      if (contract.diamondVariant === 'packed' || contract.diamondVariant === 'solidstate') {
        lines.push('let _facet := shr(96, sload(keccak256(0x00, 0x40)))');
      } else {
        lines.push('let _facet := and(sload(keccak256(0x00, 0x40)), 0xffffffffffffffffffffffffffffffffffffffff)');
      }
      if (contract.diamondVariant === 'solidstate') {
        // solidstate's headline feature: on a selector MISS, fall back to the settable default fallback
        // address (DiamondBase.fallbackAddress, the 4th field). The Proxy then requires the resolved
        // implementation to be a contract; if not (no fallback set, or it has no code) it reverts with the
        // custom error Proxy__ImplementationIsNotContract() (selector 0x87c9fc34). Byte-identical to
        // solidstate v0.0.61 DiamondFallback._getImplementation + Proxy.fallback().
        const fbSlot = String(this.diamondSlot('_fallbackAddress'));
        lines.push('if iszero(_facet) {');
        lines.push(`  _facet := and(sload(${fbSlot}), 0xffffffffffffffffffffffffffffffffffffffff)`);
        lines.push('}');
        lines.push('if iszero(extcodesize(_facet)) {');
        lines.push('  mstore(0x00, shl(224, 0x87c9fc34))'); // Proxy__ImplementationIsNotContract()
        lines.push('  revert(0x00, 0x04)');
        lines.push('}');
      } else {
        lines.push('if iszero(_facet) {');
        for (const l of this.lowerErrorString(new TextEncoder().encode('Diamond: Function does not exist')))
          lines.push('  ' + l);
        lines.push('}');
      }
      lines.push('calldatacopy(0, 0, calldatasize())');
      lines.push('let _ok := delegatecall(gas(), _facet, 0, calldatasize(), 0, 0)');
      lines.push('returndatacopy(0, 0, returndatasize())');
      lines.push('switch _ok');
      lines.push('case 0 { revert(0, returndatasize()) }');
      lines.push('default { return(0, returndatasize()) }');
    } else if (hasSpecial) {
      // Phase 6: receive/fallback dispatch (byte-identical to solc's optimized IR). The selector switch
      // is wrapped in `if iszero(lt(calldatasize(),4))` with an EMPTY default (NEVER default{revert}),
      // then the receive empty-calldata check, then the fallback (non-payable callvalue guard + body),
      // else a trailing revert. Empty calldata with no receive falls through the switch into the fallback.
      if (external.length > 0) {
        lines.push('if iszero(lt(calldatasize(), 4)) {');
        lines.push('  let selector := shr(224, calldataload(0))');
        lines.push('  switch selector');
        for (const fn of external) {
          lines.push(`  case 0x${fn.selector} { // ${fn.signature}`);
          for (const l of this.emitDispatchCase(fn)) lines.push('    ' + l);
          lines.push('  }');
        }
        lines.push('  default {}');
        lines.push('}');
      }
      if (contract.receive) {
        lines.push('if iszero(calldatasize()) {');
        for (const l of this.emitSpecialEntryBody(contract.receive)) lines.push('  ' + l);
        lines.push('  stop()');
        lines.push('}');
      }
      if (contract.fallback) {
        if (!contract.fallback.payable) lines.push('if callvalue() { revert(0, 0) }');
        for (const l of this.emitSpecialEntryBody(contract.fallback)) lines.push(l);
        // Fall-off the end with no return: solc returns the default `bytes memory` value, whose RAW
        // returndata content is EMPTY (a fallback's bytes return is the literal returndata, not an
        // ABI-encoded tuple - so empty, not [0x20][0]). A bare (void) fallback halts via stop(); both
        // produce empty returndata, so stop() is byte-identical for either form.
        lines.push('stop()');
      } else {
        lines.push('revert(0, 0)');
      }
    } else if (external.length === 0) {
      // No externally-callable functions: any call reverts. (Avoid emitting a
      // `switch` with only a default, which solc warns about.)
      lines.push('revert(0, 0)');
    } else {
      lines.push('if lt(calldatasize(), 4) { revert(0, 0) }');
      lines.push('let selector := shr(224, calldataload(0))');
      lines.push('switch selector');
      for (const fn of external) {
        lines.push(`case 0x${fn.selector} { // ${fn.signature}`);
        for (const l of this.emitDispatchCase(fn)) lines.push('  ' + l);
        lines.push('}');
      }
      lines.push('default { revert(0, 0) }');
    }

    // Emit a Yul function definition for every function that is called internally (G8).
    // (A purely-internal function never called is dead and elided, matching solc.)
    for (const fn of contract.functions) {
      if (fn.internallyCalled) {
        lines.push('');
        lines.push(this.emitInternalFunction(fn));
      }
    }

    // Append helper function definitions (deduplicated). Some are added while lowering
    // the internal functions above, so this must come last.
    for (const def of this.helpers.values()) {
      lines.push('');
      lines.push(def);
    }
    return lines.join('\n');
  }

  /** Phase 6: lower a @receive/@fallback body INLINE in the dispatcher (no params, no return). A bare
   *  `return;` halts via stop() (specialEntry flag). The caller appends the trailing stop(). */
  private emitSpecialEntryBody(entry: SpecialEntryIR): string[] {
    const ctx: LowerCtx = {
      scopes: [new Map()],
      returnType: entry.returnsBytes ? ({ kind: 'bytes' } as JethType) : ({ kind: 'void' } as JethType),
      dynParams: new Map(),
      cdArrays: new Map(),
      cdAggregates: new Map(),
      cdDynStructs: new Map(),
      cdParamHead: new Map(),
      specialEntry: true,
    };
    // The data-passing @fallback's bytes param is the WHOLE calldata (== msg.data): bind it as a
    // calldata bytes view (dataPtr 0, len calldatasize()), exactly like solc's `bytes calldata input`.
    // A `return <bytes>` ABI-encodes + returns it (the general bytes-return path); a bare `return;` /
    // fall-off returns empty bytes (handled by the dispatcher caller).
    if (entry.bytesParam) ctx.dynParams.set(entry.bytesParam, { dataPtr: '0', len: 'calldatasize()' });
    const out: string[] = [];
    for (const s of entry.body) for (const l of this.lowerStmt(s, ctx)) out.push(l);
    return out;
  }

  /** A Yul `function userfn_<name>(args) -> ret { body }` for an internally-called function.
   *  Params bind to the Yul args (already-clean JETH values - no calldata decode/validation);
   *  `return v` inside the body sets `ret` and `leave`s (see lowerStmt 'return' fnMode). */
  private emitInternalFunction(fn: FunctionIR, ctorImmShadow?: Map<string, string>): string {
    this.nameCounter = 0;
    const ctx: LowerCtx = {
      scopes: [new Map()],
      returnType: fn.returnType,
      dynParams: new Map(),
      cdArrays: new Map(),
      cdAggregates: new Map(),
      cdDynStructs: new Map(),
      cdParamHead: new Map(),
      // When this is a CREATION-block copy of a ctor-reachable helper, an @immutable read uses the
      // staged-value memory cell (mload) instead of loadimmutable (solc forbids the latter alongside
      // setimmutable in one subroutine). Undefined for the normal runtime-object copy.
      ctorImmShadow,
    };
    const argNames: string[] = [];
    for (const p of fn.params) {
      const an = this.freshLocal(p.name);
      this.ctxDeclare(ctx, p.name, an);
      argNames.push(an);
    }
    let retDecl = '';
    // P0-3: an AGGREGATE / bytes / string return var holds a MEMORY POINTER, not a value. A Yul return
    // var is 0-initialized, so on a SKIP / FALL-THROUGH path (the function runs off its end, or an early
    // guarded branch is not taken) it would be a null pointer into scratch memory - JETH then re-encodes
    // whatever garbage lives at memory 0 (keccak scratch / an attacker-influenceable mapping key or
    // length). solc returns the type's ZERO VALUE there. Initialize each aggregate/bytes/string return
    // var to a fresh zero image at entry (a value-type var correctly defaults to 0 and needs no init).
    const needsZeroImage = (t: JethType): boolean => t.kind === 'struct' || t.kind === 'array' || isBytesLike(t);
    const zeroInits: string[] = [];
    if (fn.returnTypes) {
      // a multi-value internal function: `-> r0, r1, ...`; `return [..]` sets each and leaves.
      const retVars = fn.returnTypes.map(() => this.fresh());
      ctx.fnMode = { retVar: null, retVars };
      retDecl = ` -> ${retVars.join(', ')}`;
      fn.returnTypes.forEach((rt, i) => {
        if (needsZeroImage(rt)) zeroInits.push(`${retVars[i]} := ${this.zeroImageFor(rt, ctx, zeroInits)}`);
      });
    } else {
      const retVar = fn.returnType.kind === 'void' ? null : this.fresh();
      ctx.fnMode = { retVar };
      retDecl = retVar ? ` -> ${retVar}` : '';
      if (retVar && needsZeroImage(fn.returnType))
        zeroInits.push(`${retVar} := ${this.zeroImageFor(fn.returnType, ctx, zeroInits)}`);
    }
    const body: string[] = [...zeroInits];
    for (const s of fn.body) for (const l of this.lowerStmt(s, ctx)) body.push(l);
    const sig = `function ${this.userFnName(fn.key)}(${argNames.join(', ')})${retDecl}`;
    return `${sig} {\n${body.map((l) => '  ' + l).join('\n')}${body.length ? '\n' : ''}}`;
  }

  private userFnName(name: string): string {
    return `userfn_${name}`;
  }

  private emitDispatchCase(fn: FunctionIR): string[] {
    const out: string[] = [];
    this.nameCounter = 0; // deterministic, function-local unique names
    if (fn.mutability !== 'payable') {
      out.push('if callvalue() { revert(0, 0) } // reject value to non-payable');
    }
    // Phase 2c (UUPS): a synthesized @uups entry has a hand-written body (no source `body`/params to
    // lower). The callvalue guard above already matches OZ (upgradeToAndCall is payable -> no guard;
    // proxiableUUID is view -> guard). Emit the dedicated body and return.
    if (fn.uupsKind) {
      for (const l of this.emitUupsEntry(fn)) out.push(l);
      return out;
    }
    // Phase 2d (BEACON): a synthesized @beacon entry has a hand-written body (the OZ UpgradeableBeacon 5.x
    // surface). The callvalue guard above matches OZ (all three are non-payable: view getters + upgradeTo).
    if (fn.beaconKind) {
      for (const l of this.emitBeaconEntry(fn)) out.push(l);
      return out;
    }

    // Decode params from calldata. Each param has one head word at 4+32*i; a
    // dynamic (bytes/string) head word is a tail offset, decoded into (ptr,len).
    const ctx: LowerCtx = {
      scopes: [new Map()],
      returnType: fn.returnType,
      dynParams: new Map(),
      cdArrays: new Map(),
      cdAggregates: new Map(),
      cdDynStructs: new Map(),
      cdParamHead: new Map(),
    };
    // The static head is a flat, gapless run of 32-byte words; each param consumes
    // abiHeadWords(type) of them (a static aggregate occupies one word per leaf,
    // NOT one word total; a dynamic param occupies one offset word). solc rejects
    // calldata shorter than the full static head with an empty revert.
    // A dynamic param (bytes/string, dynamic array, OR a dynamic struct) occupies
    // exactly ONE head word (an offset). A static aggregate occupies abiHeadWords.
    const paramHeadWords = (t: JethType): number => (isDynamicType(t) ? 1 : abiHeadWords(t));
    const staticHeadWords = fn.params.reduce((n, p) => n + paramHeadWords(p.type), 0);
    if (staticHeadWords > 0) {
      out.push(`if lt(calldatasize(), ${4 + 32 * staticHeadWords}) { revert(0, 0) }`);
    }
    let cursorWords = 0;
    for (const p of fn.params) {
      const head = 4 + 32 * cursorWords;
      ctx.cdParamHead.set(p.name, { head, type: p.type });
      if (p.type.kind === 'struct' && isDynamicType(p.type)) {
        // dynamic struct param: head word = offset to the tuple start (base = byte 4).
        // Decode the offset and length-readable range check; bind the tuple-start
        // calldata byte pointer. Field reads resolve lazily (spec section 3.2).
        const off = this.fresh();
        const tupleStart = this.fresh();
        const headSize = tupleHeadWords(p.type) * 32;
        out.push(`let ${off} := calldataload(${head})`);
        out.push(`let ${tupleStart} := ${this.calldataTuple()}(${off}, ${headSize})`);
        ctx.cdDynStructs.set(p.name, { tupleStart, type: p.type });
      } else if (p.type.kind === 'array' && p.type.length !== undefined && isDynamicType(p.type.element)) {
        // Arr<dyn,N>: a FIXED array of a DYNAMIC element. A dynamic param: head word =
        // offset to the N-word per-element offset table (base = table start, NO length
        // word). Bound it as a length-N calldata array so a[i] / echo reuse the
        // dynamic-array machinery.
        const off = this.fresh();
        out.push(`let ${off} := calldataload(${head})`);
        // UNSIGNED offset cap (matching the sibling top-level decoders + solc): a high-bit
        // "negative" offset must EMPTY-revert here, not wrap to a small in-bounds pointer (which
        // would later raise Panic 0x32 and diverge from solc's empty revert).
        out.push(`if gt(${off}, 0xffffffffffffffff) { revert(0, 0) }`);
        const dataPtr = this.fresh();
        out.push(`let ${dataPtr} := add(4, ${off})`);
        // the WHOLE N-word per-element offset table (no length word) must be readable: solc
        // requires dataPtr + N*32 <= calldatasize, not just the first word (a head that fits its
        // first word but runs past calldatasize for words 1..N-1 must EMPTY-revert, like solc).
        out.push(`if gt(add(${dataPtr}, ${p.type.length * 32}), calldatasize()) { revert(0, 0) }`);
        ctx.cdArrays.set(p.name, { offset: dataPtr, length: String(p.type.length), elem: p.type.element });
      } else if (p.type.kind === 'struct' || (p.type.kind === 'array' && p.type.length !== undefined)) {
        // static aggregate: inline in the head, decoded lazily on field/element read.
        ctx.cdAggregates.set(p.name, { baseOffset: head, type: p.type });
      } else if (p.type.kind === 'array' && p.type.length === undefined && isDynamicType(p.type.element)) {
        // Array of DYNAMIC elements: string[]/bytes[] (4e-4), nested T[][] (4e-5), OR a
        // dynamic-struct array D[]. All share the outer header: [length] then a
        // per-element offset table. `offset` is the table start (= the word after the
        // length word), which is ALSO the per-element offset base (spec sections 2-4).
        // Per-element offsets are resolved lazily on a[i] / m[i] / d[i] access.
        const off = this.fresh();
        const tableStart = this.fresh();
        const length = this.fresh();
        out.push(`let ${off} := calldataload(${head})`);
        out.push(`let ${tableStart}, ${length} := ${this.calldataDynArray()}(${off})`);
        ctx.cdArrays.set(p.name, { offset: tableStart, length, elem: p.type.element });
      } else if (p.type.kind === 'array') {
        const off = this.fresh();
        const offset = this.fresh();
        const length = this.fresh();
        const stride = abiHeadWords(p.type.element) * 32; // ABI element stride (unpacked)
        out.push(`let ${off} := calldataload(${head})`);
        out.push(`let ${offset}, ${length} := ${this.calldataArray()}(${off}, ${stride})`);
        ctx.cdArrays.set(p.name, { offset, length, elem: p.type.element });
      } else if (isBytesLike(p.type)) {
        const off = this.fresh();
        const dataPtr = this.fresh();
        const len = this.fresh();
        out.push(`let ${off} := calldataload(${head})`);
        out.push(`let ${dataPtr}, ${len} := ${this.calldataDyn()}(${off})`);
        ctx.dynParams.set(p.name, { dataPtr, len });
      } else {
        // Route params through the same unique-name allocator as locals so a param
        // named `<base>_<k>` can never collide with a local `<base>` in Yul.
        const name = this.freshLocal(p.name);
        this.ctxDeclare(ctx, p.name, name);
        out.push(`let ${name} := calldataload(${head})`);
        const guard = this.validateInput(p.type, name);
        if (guard) out.push(guard);
      }
      cursorWords += paramHeadWords(p.type);
    }

    const bodyLines: string[] = [];
    if (fn.modifierWrap) {
      // Phase 5 (FULL MODIFIERS): at least one applied modifier has post-placeholder code (or a
      // conditional placeholder / multiple placeholders / a `return;`). The wrapped body Z is the
      // synthesized body function userfn_<key> (forced internallyCalled); the dispatch lowers modifierWrap
      // (the nested pre/post block structure) where EACH {modifierBody} marker calls userfn_<key>(<args>)
      // and captures its result(s) into the buffered `retVars`. A `return` inside Z sets userfn's ret and
      // `leave`s, so it runs no further BODY code but returns here, letting the enclosing post-code run
      // BEFORE the value is ABI-encoded ONCE. userfn_<key> is a normal internal function, so it supports
      // aggregate/dynamic params + a multi-value / aggregate return (JETH323); a bare `return;` in the
      // modifier body encodes the CURRENT retVars + returns (JETH325).
      // retVars: one buffered var per return value. A MULTI-VALUE function has returnTypes set (and a
      // VOID returnType placeholder), so check returnTypes FIRST; otherwise a void function has none and
      // a single-value/bytes/string/aggregate function has one.
      const retVars = fn.returnTypes
        ? fn.returnTypes.map(() => this.fresh())
        : fn.returnType.kind === 'void'
          ? []
          : [this.fresh()];
      // Zero-init each buffered return var so a 0-times / early-`return;` path returns solc's zero value.
      // P0-4: an AGGREGATE / bytes / string var holds a MEMORY POINTER, so `let r := 0` (a null pointer)
      // makes the shared return encoder re-encode scratch memory (an attacker-influenceable mapping key /
      // length) - initialize it to a fresh zero IMAGE instead; a value var correctly gets `:= 0`.
      const retTypes = fn.returnTypes ?? (fn.returnType.kind === 'void' ? [] : [fn.returnType]);
      const needsZeroImage = (t: JethType): boolean => t.kind === 'struct' || t.kind === 'array' || isBytesLike(t);
      retVars.forEach((r, i) => {
        const rt = retTypes[i]!;
        if (needsZeroImage(rt)) bodyLines.push(`let ${r} := ${this.zeroImageFor(rt, ctx, bodyLines)}`);
        else bodyLines.push(`let ${r} := 0`);
      });
      ctx.modifierDispatch = {
        userFn: this.userFnName(fn.key),
        args: this.lowerCallArgs(fn.modifierArgs ?? [], ctx, bodyLines),
        retVars,
        returnType: fn.returnType,
        returnTypes: fn.returnTypes,
      };
      for (const s of fn.modifierWrap) for (const l of this.lowerStmt(s, ctx)) bodyLines.push(l);
      // Encode the buffered return value(s) ONCE (same encoder a `return;` early-out uses).
      for (const l of this.emitModifierReturn(ctx.modifierDispatch, ctx)) bodyLines.push(l);
      if (fn.nonReentrant) {
        out.push(`if tload(${REENTRANCY_TSLOT}) { mstore(0, ${REENTRANCY_ERROR_WORD}) revert(0, 4) }`);
        out.push(`tstore(${REENTRANCY_TSLOT}, 1)`);
        for (const l of bodyLines) {
          if (l.trimStart().startsWith('return(')) out.push(`tstore(${REENTRANCY_TSLOT}, 0)`);
          out.push(l);
        }
      } else {
        out.push(...bodyLines);
      }
      return out;
    }

    const last = fn.body[fn.body.length - 1];
    const terminates =
      last !== undefined && (last.kind === 'return' || last.kind === 'revert' || last.kind === 'returnTuple');
    // Lower the body + fall-through epilogue into a local buffer; a @nonReentrant function then
    // brackets it with the transient mutex (resetting before every normal return).
    for (const s of fn.body) {
      for (const l of this.lowerStmt(s, ctx)) bodyLines.push(l);
    }
    if (!terminates && fn.returnTypes) {
      // P0-12: fall-through default for a MULTI-VALUE return - solc returns the zero TUPLE. The old code
      // used one head word per component (wrong for a STATIC aggregate, which occupies abiHeadWords words)
      // and gave a plain `0` (not an offset word) to a dynamic ARRAY component. Encode the exact zero tuple
      // via the shared structural encoder (static components inline; dynamic components offset + empty tail).
      const { ptr, size } = this.encodeZeroReturnMulti(fn.returnTypes, bodyLines);
      bodyLines.push(`return(${ptr}, ${size})`);
    } else if (!terminates) {
      // void or fall-through: return the default-encoded value, matching Solidity (falling off the end
      // returns the ABI encoding of the return type's ZERO value).
      if (fn.returnType.kind === 'void') bodyLines.push('return(0, 0)');
      else if (fn.returnType.kind === 'struct' || fn.returnType.kind === 'array' || isBytesLike(fn.returnType)) {
        // P0-12: use the shared structural zero encoder. A STATIC struct / static array is inline zero
        // words (NOT the dynamic [0x20][0] blob the old array branch emitted); a DYNAMIC struct is the
        // [0x20] wrapper + a zero tuple with dynamic-field tails (NOT flat inline words); a dynamic array /
        // bytes / string keeps [0x20][0]; a fixed-of-dynamic array is [0x20] + an offset table + empty tails.
        const { ptr, size } = this.encodeZeroReturnSingle(fn.returnType, bodyLines);
        bodyLines.push(`return(${ptr}, ${size})`);
      } else bodyLines.push('mstore(0, 0)', 'return(0, 0x20)');
    }

    if (fn.nonReentrant) {
      // ENTER: trip the guard if already entered (revert ReentrancyGuardReentrantCall()), else set
      // it. EXIT: reset the transient slot before every NORMAL return; a revert auto-rolls-back
      // transient storage per EIP-1153, so revert paths need no explicit reset.
      out.push(`if tload(${REENTRANCY_TSLOT}) { mstore(0, ${REENTRANCY_ERROR_WORD}) revert(0, 4) }`);
      out.push(`tstore(${REENTRANCY_TSLOT}, 1)`);
      for (const l of bodyLines) {
        if (l.trimStart().startsWith('return(')) out.push(`tstore(${REENTRANCY_TSLOT}, 0)`);
        out.push(l);
      }
    } else {
      out.push(...bodyLines);
    }
    return out;
  }

  /** Phase 5 (full modifiers): encode the buffered modifier-dispatch return var(s) ONCE and emit the
   *  Yul `return(...)`. Reused by the dispatch's final encode AND by a bare `return;` inside the modifier
   *  body (JETH325) - both return the CURRENT buffered values. Void -> empty return; a multi-value return
   *  re-uses the tuple encoder via a synthetic `returnTuple` of rawReg components; a single value / bytes
   *  / string / aggregate return re-uses the single-value return encoder via a synthetic `return`. The
   *  rawReg value(s) carry the original return type(s) so the encoder picks the right codec (a value reg,
   *  a bytes/string/array/struct memory pointer). */
  private emitModifierReturn(md: NonNullable<LowerCtx['modifierDispatch']>, ctx: LowerCtx): string[] {
    const out: string[] = [];
    if (md.returnTypes) {
      this.lowerStmt(
        {
          kind: 'returnTuple',
          values: md.retVars.map((r, i) => ({ kind: 'rawReg', type: md.returnTypes![i]!, reg: r })),
          types: md.returnTypes,
        },
        ctx,
      ).forEach((l) => out.push(l));
    } else if (md.retVars.length === 1) {
      const rt = md.returnType;
      const reg = md.retVars[0]!;
      // An AGGREGATE return: the buffered var holds a MEMORY POINTER (the userfn returns a struct/array
      // image pointer, like a struct-returning internal call). Bind it to a synthetic ctx local and emit
      // the matching MEMORY-SOURCE return Expr so the encoder is byte-identical to `return <memLocal>`.
      // bytes/string + value types use the rawReg single-value return (which lowerDynamic/lowerExpr both
      // handle from a register / a memory ptr). The analyzer gates aggregate returns to this safe set.
      if ((rt.kind === 'struct' || rt.kind === 'array') && !isBytesLike(rt)) {
        const local = `__jeth_mret_${this.fresh().replace(/[^a-zA-Z0-9_]/g, '')}`;
        this.ctxDeclare(ctx, local, reg);
        const memExpr: Expr =
          rt.kind === 'array' && (rt.length === undefined || isDynamicType(rt.element))
            ? { kind: 'arrayValue', type: rt, arr: { base: { kind: 'memArray', varName: local }, elem: rt.element } }
            : rt.kind === 'struct' && isDynamicType(rt)
              ? { kind: 'memDynStructValue', type: rt, local }
              : { kind: 'memAggregate', type: rt, local };
        this.lowerStmt({ kind: 'return', value: memExpr }, ctx).forEach((l) => out.push(l));
      } else {
        this.lowerStmt({ kind: 'return', value: { kind: 'rawReg', type: rt, reg } }, ctx).forEach((l) => out.push(l));
      }
    } else {
      out.push('return(0, 0)'); // void
    }
    return out;
  }

  /** Emit a validation guard for a decoded static value-type input, or '' if the
   *  full 32-byte word is always valid. Reverts with empty returndata on dirty
   *  input, matching Solidity's ABI decoder (verified against solc 0.8). */
  private validateInput(t: JethType, name: string): string {
    // an enum (branded uint8) decodes like uint8 but with the TIGHTER `< memberCount` check:
    // an out-of-range enum value reverts EMPTY in solc (ABI validation failure, not a Panic).
    const em = (t as { enumMembers?: string[] }).enumMembers;
    if (t.kind === 'uint' && em !== undefined) {
      return `if iszero(lt(${name}, ${em.length})) { revert(0, 0) }`;
    }
    switch (t.kind) {
      case 'uint':
        // uintN<256: high bits must be zero.
        return t.bits === 256 ? '' : `if gt(${name}, ${uintMaxHex(t.bits)}) { revert(0, 0) }`;
      case 'int':
        // intN<256: must be a valid sign-extension of its low bytes.
        return t.bits === 256 ? '' : `if iszero(eq(signextend(${t.bits / 8 - 1}, ${name}), ${name})) { revert(0, 0) }`;
      case 'bool':
        return `if gt(${name}, 1) { revert(0, 0) }`;
      case 'address':
        // high 96 bits must be zero.
        return `if shr(160, ${name}) { revert(0, 0) }`;
      case 'bytesN':
        // bytesN<32 is left-aligned: the low (32-size) bytes must be zero.
        return t.size === 32 ? '' : `if and(${name}, ${bytesNLowMaskHex(t.size)}) { revert(0, 0) }`;
      default:
        throw new UnsupportedError(`calldata decoding for type '${t.kind}' is not supported yet (Phase 4)`);
    }
  }

  /** Clean a calldata element word into its in-register form (mask / sign-extend /
   *  normalize), without reverting on dirty bits. Matches solc's array copy. */
  private cleanCalldataElem(t: JethType, w: string): string {
    switch (t.kind) {
      case 'uint':
        return t.bits === 256 ? w : `and(${w}, ${uintMaxHex(t.bits)})`;
      case 'int':
        return t.bits === 256 ? w : `signextend(${t.bits / 8 - 1}, ${w})`;
      case 'bool':
        return `iszero(iszero(${w}))`;
      case 'address':
        return `and(${w}, ${uintMaxHex(160)})`;
      case 'bytesN': {
        if (t.size === 32) return w;
        const highMask = ((1n << BigInt(t.size * 8)) - 1n) << BigInt((32 - t.size) * 8);
        return `and(${w}, ${toWord(highMask)})`;
      }
      default:
        return w;
    }
  }

  /** Member count when `t` is an enum-branded uint8, else undefined. */
  private enumCount(t: JethType): number | undefined {
    const em = (t as { enumMembers?: string[] }).enumMembers;
    return t.kind === 'uint' && em !== undefined ? em.length : undefined;
  }

  /** The ultimate leaf of a (possibly nested FIXED) array type; identity for non-arrays. */
  private arrayLeaf(t: JethType): JethType {
    return t.kind === 'array' ? this.arrayLeaf(t.element) : t;
  }

  /** W6C: Panic(0x21) on any out-of-range ENUM word inside a VALUE-LEAF memory array image whose
   *  data words are INLINE (a flat [len][words] dynamic image, or a fixed inline block - NOT a
   *  pointer-headed image). No-op unless the leaf is an enum. This is solc's validator_assert
   *  flavor: encoding/copying an enum array OUT of memory (return / abi.encode / emit / error /
   *  mem->storage) range-checks every element and Panics 0x21 on the first dirty one. The memory
   *  image can hold raw dirty words because the calldata->memory BIND copy is raw (calldatacopy
   *  semantics, matching solc - lazy validation). Valid images make this a pure no-op. */
  private validateEnumMemArray(t: JethType, memPtr: string, out: string[]): void {
    // a STATIC STRUCT image (flat ABI-unpacked words): range-check each ENUM leaf word. A struct
    // image can inherit a RAW dirty word when a raw-bound fixed enum array is a constructor arg
    // (Q(b, i)); solc Panics 0x21 when encoding it out of memory. No-op without enum leaves.
    if (t.kind === 'struct' && isStaticType(t)) {
      for (const lf of abiLeaves(t)) {
        const n = this.enumCount(lf.type);
        if (n === undefined) continue;
        const at = lf.wordOffset === 0 ? memPtr : `add(${memPtr}, ${lf.wordOffset * 32})`;
        out.push(`if iszero(lt(mload(${at}), ${n})) { ${this.panic()}(0x21) }`);
      }
      return;
    }
    if (t.kind !== 'array' || !isValueLeafArray(t)) return;
    const n = this.enumCount(this.arrayLeaf(t));
    if (n === undefined) return;
    const i = this.fresh();
    if (t.length === undefined) {
      // dynamic outer with a STATIC inline element ([len] + len*ew inline words). A pointer-headed
      // (dynamic-element) image never reaches here: those binds validate eagerly at the copy.
      if (!(isStaticType(t.element) && isStaticValueType(this.arrayLeaf(t.element)))) return;
      const ew = t.element.kind === 'array' ? abiHeadWords(t.element) * 32 : 32;
      const total = this.fresh();
      out.push(`let ${total} := mul(mload(${memPtr}), ${ew})`);
      out.push(`for { let ${i} := 0 } lt(${i}, ${total}) { ${i} := add(${i}, 0x20) } {`);
      out.push(`  if iszero(lt(mload(add(add(${memPtr}, 0x20), ${i})), ${n})) { ${this.panic()}(0x21) }`);
      out.push(`}`);
      return;
    }
    if (!isStaticValueType(this.arrayLeaf(t))) return; // pointer-headed fixed image: not inline words
    out.push(`for { let ${i} := 0 } lt(${i}, ${abiHeadWords(t) * 32}) { ${i} := add(${i}, 0x20) } {`);
    out.push(`  if iszero(lt(mload(add(${memPtr}, ${i})), ${n})) { ${this.panic()}(0x21) }`);
    out.push(`}`);
  }

  // ---- statements ----------------------------------------------------------

  private lowerStmt(s: Stmt, ctx: LowerCtx): string[] {
    const out: string[] = [];
    switch (s.kind) {
      case 'returnTuple': {
        // inside a multi-value INTERNAL function: set each return var (left-to-right) and leave.
        if (ctx.fnMode) {
          const vars = ctx.fnMode.retVars ?? [];
          // a value component is a plain register; an AGGREGATE component (struct / dynamic
          // value array / bytes / string) is materialized to a fresh MEMORY image and the
          // return var holds its pointer (same alias/copy rules as a single aggregate return).
          s.values.forEach((v, i) => {
            const rt = v.type;
            const isAgg = rt.kind === 'struct' || rt.kind === 'array' || isBytesLike(rt);
            const reg = isAgg ? this.aggArgToMemPtr(v, ctx, out) : this.lowerExpr(v, ctx, out);
            out.push(`${vars[i]} := ${reg}`);
          });
          out.push('leave');
          break;
        }
        const { ptr, size } = this.encodeReturnTuple(s.values, s.types, ctx, out);
        out.push(`return(${ptr}, ${size})`);
        break;
      }
      case 'return': {
        // Inside an INTERNAL function (G8/G9): set the return var and `leave`. A value return
        // sets ret to the value; a STATIC struct return sets ret to the memory pointer (a freshly
        // constructed struct is allocated first). A bare `return;` in a void fn just leaves.
        if (ctx.fnMode) {
          if (s.value && ctx.fnMode.retVar) {
            // an aggregate return (struct / dynamic value array / bytes / string) yields a MEMORY
            // pointer (same alias/copy rules as an argument); a value return is a plain register.
            const rt = s.value.type;
            const isAgg = rt.kind === 'struct' || rt.kind === 'array' || isBytesLike(rt);
            const v = isAgg ? this.aggArgToMemPtr(s.value, ctx, out) : this.lowerExpr(s.value, ctx, out);
            out.push(`${ctx.fnMode.retVar} := ${v}`);
          }
          out.push('leave');
          break;
        }
        if (!s.value) {
          // Phase 5 (JETH325): a bare `return;` inside a modifier body (lowered in the dispatch, where
          // ctx.modifierDispatch is set but ctx.fnMode is not) early-exits the wrapped function with the
          // CURRENT buffered return values - encode them ONCE and return, byte-identical to solc.
          if (ctx.modifierDispatch) {
            for (const l of this.emitModifierReturn(ctx.modifierDispatch, ctx)) out.push(l);
            break;
          }
          // a @receive/@fallback body's bare `return;` halts via stop() (byte-identical to solc), not
          // return(0,0); a normal void function returns empty calldata.
          out.push(ctx.specialEntry ? 'stop()' : 'return(0, 0)');
          break;
        }
        // Phase 3 DIAMOND: `return __diamondFacets()` (the facets() loupe). Build the Facet[] ABI return
        // blob in raw Yul directly from the split diamond-3 storage (no JETH Facet[] memory local exists).
        if (s.value.kind === 'diamondFacets') {
          this.lowerDiamondFacetsReturn(out);
          break;
        }
        // Phase 3 DIAMOND (packed): the three diamond-2 loupe reconstructors. Each rebuilds the facet
        // grouping in memory from the packed selectorSlots + the facets mapping (raw Yul).
        if (s.value.kind === 'diamondFacetsPacked') {
          this.lowerDiamondFacetsReturnPacked(out);
          break;
        }
        if (s.value.kind === 'diamondFacetSelectorsPacked') {
          this.lowerDiamondFacetSelectorsReturnPacked(s.value.facet, ctx, out);
          break;
        }
        if (s.value.kind === 'diamondFacetAddressesPacked') {
          this.lowerDiamondFacetAddressesReturnPacked(out);
          break;
        }
        // `return xs[i].grid` / `return xs[i].items` (a whole DYNAMIC-ARRAY field of a calldata
        // dyn-struct array element used as a value): re-encode the whole array from its calldata
        // header via the recursive calldata codec.
        if (s.value.kind === 'cdFieldAggValue') {
          const { ptr, size } = this.echoCdFieldArray(s.value.place, s.value.type, ctx, out);
          out.push(`return(${ptr}, ${size})`);
          break;
        }
        // `return xs[i].grid[j]` (a whole INNER array reached by descending such a nested-array field):
        // descend the per-level offset tables to the inner array header, then re-encode whole.
        if (s.value.kind === 'cdNestedFieldAggValue') {
          const { ptr, size } = this.echoCdNestedFieldArray(s.value.place, s.value.indices, s.value.type, ctx, out);
          out.push(`return(${ptr}, ${size})`);
          break;
        }
        // `return p` (memory STATIC struct local), `return p.inner` (a nested struct field, a
        // sub-pointer), or `return this.helper()` (struct-returning internal call): the
        // ABI-unpacked memory image at the (sub)pointer IS the flat return blob. G9.
        if (
          isStaticType(s.value.type) &&
          (s.value.type.kind === 'struct' || s.value.type.kind === 'array') &&
          // Batch A: a STATIC fixed-outer static-struct array (Arr<P,N>) whose memory image is
          // POINTER-HEADED (a memAggregate local, an internal-call return, a struct-array element, or a
          // static-aggregate field of a struct-array element) is NOT the inline ABI blob - it falls to the
          // codec return branch below (abiEncFromMem flattens the pointer words inline). A ternary / bn256
          // materializes its branches via aggToMemPtr (INLINE for the storage/literal branches that were
          // the only reachable pre-Batch-A sources), so those stay on this verbatim flat-image path.
          // POINTER-HEADED Arr<P,N> sources: a memAggregate local, an internal-call return, and a
          // struct-array element m[i] (Arr<P,N>[] element). A static-aggregate FIELD (aggFieldRead, e.g.
          // xs[i].pre) is ABI-FLATTENED INLINE in its containing struct image, so it stays verbatim below.
          !(isStaticStructFixedLeafArray(s.value.type) &&
            (s.value.kind === 'memAggregate' || s.value.kind === 'call' || s.value.kind === 'arrayGet')) &&
          (s.value.kind === 'memAggregate' ||
            s.value.kind === 'call' ||
            s.value.kind === 'ternary' ||
            s.value.kind === 'bn256' ||
            // Residual B1: `return xs[i]` (a static-struct element of a P[] memory local). The
            // arrayGet lowers to the element's inline image BASE pointer, which IS the flat return blob.
            (s.value.kind === 'arrayGet' && s.value.type.kind === 'struct') ||
            // B4 / B3: `return p.inner` / `return p.fa` (a whole nested STATIC AGGREGATE field of a
            // dyn-struct memory local), or `return xs[i].q` / `return xs[i].pre` (a whole static-aggregate
            // field of a struct-array element). aggFieldRead lowers to the field's inline sub-image pointer,
            // which IS the flat return blob (the image stores clean ABI head words). A DYNAMIC field
            // (bytes/dyn-array, deref'd) is not a static struct/array, so it is excluded by isStaticType.
            s.value.kind === 'aggFieldRead')
        ) {
          // a STATIC memory-aggregate image (struct / fixed array): the image IS the flat return blob.
          // (A DYNAMIC-array call/ternary falls through to encodeMemArrayReturn below.)
          const ptr = this.fresh();
          out.push(`let ${ptr} := ${this.lowerExpr(s.value, ctx, out)}`);
          // W6C: a fixed ENUM array image (`const b: Arr<Color,3> = a; return b;`) is range-checked
          // on the way out (Panic 0x21) - the image may hold RAW dirty words from the bind copy.
          this.validateEnumMemArray(s.value.type, ptr, out);
          out.push(`return(${ptr}, ${abiHeadWords(s.value.type) * 32})`);
          break;
        }
        // `return a` (whole STATIC struct / fixed-array calldata param): re-encode inline
        // from the param head (flat, no offset wrapper). G5.
        if (s.value.kind === 'cdAggregateValue') {
          const { ptr, size } = this.echoStaticParam(s.value.param, s.value.type, ctx, out);
          out.push(`return(${ptr}, ${size})`);
          break;
        }
        // `return ps[i]` (whole struct element of a calldata struct array): bounds-check i
        // (Panic 0x32), then re-encode the element from its calldata head into a fresh ABI
        // return blob (a STATIC struct flat, a DYNAMIC struct with the [0x20] wrapper).
        if (s.value.kind === 'cdStructArrayElem') {
          const { ptr, size } = this.returnCdArrayElem(s.value.arr, s.value.index, s.value.type, ctx, out);
          out.push(`return(${ptr}, ${size})`);
          break;
        }
        // LIFT #1: `return xs[i]` (whole sub-aggregate element of a calldata array-of-array): the SAME
        // bounds-check + calldata-codec re-encode as a struct element (returnCdArrayElem is type-generic:
        // a STATIC element is flat, a DYNAMIC element gets the [0x20] wrapper). solc treats this as a
        // calldata->memory DECODE/copy: an oversized inner length / alloc overflow EMPTY-reverts (NOT
        // Panic 0x41) - empirically verified vs solc 0.8.35 for both a value-leaf (u256[][]) and a
        // static-struct-leaf (P[][]) element - so pass capEmptyRevert = true.
        if (s.value.kind === 'cdAggArrayElem') {
          const { ptr, size } = this.returnCdArrayElem(s.value.arr, s.value.index, s.value.type, ctx, out, true);
          out.push(`return(${ptr}, ${size})`);
          break;
        }
        // `return this.m[k]` (whole struct/array mapping value): encode from the
        // runtime mapping slot via the storage-source encoder.
        if (s.value.kind === 'mapStorageValue') {
          const slot = this.mappingSlot(s.value.baseSlot, s.value.keys, ctx, out);
          const { ptr, size } = this.returnStorageValue(slot, s.value.type, out);
          out.push(`return(${ptr}, ${size})`);
          break;
        }
        // `return this.recs[i]` (whole struct array element): encode from the
        // bounds-checked element slot via the storage-source encoder.
        if (s.value.kind === 'structArrayElem') {
          const slot = this.structArrayElemSlot(s.value.arr, s.value.index, ctx, out);
          const { ptr, size } = this.returnStorageValue(slot, s.value.type, out);
          out.push(`return(${ptr}, ${size})`);
          break;
        }
        // `return this.recs[i].inner` (whole nested-struct field) / `return this.g3[i][j]`
        // (whole fixed-array leaf at depth): fold the path to the slot, then encode via the
        // storage-source encoder.
        if (s.value.kind === 'placeRead' && (s.value.type.kind === 'struct' || s.value.type.kind === 'array')) {
          const p = this.lowerPlace(s.value.path, ctx, out);
          const { ptr, size } = this.returnStorageValue(p.slot, s.value.type, out);
          out.push(`return(${ptr}, ${size})`);
          break;
        }
        if (isBytesLike(s.value.type)) {
          // A data-passing @fallback's `return <bytes>` returns the RAW bytes CONTENT (no ABI [0x20][len]
          // wrapper): solc's fallback/bytes-return is the literal returndata, not an ABI-encoded tuple.
          // Materialize the bytes into a [len][data] image, then return (dataPtr, len) directly.
          if (ctx.specialEntry) {
            const { mp, len } = this.toMemory(this.lowerDynamic(s.value, ctx, out), out);
            out.push(`return(add(${mp}, 0x20), ${len})`);
            break;
          }
          const ref = this.lowerDynamic(s.value, ctx, out);
          const { ptr, size } = this.encodeDynToMem(ref, out);
          out.push(`return(${ptr}, ${size})`);
          break;
        }
        if (s.value.type.kind === 'array') {
          // S4: `return n.arr` - a whole STATIC fixed-array LEAF (Arr<u256,2>, Arr<Arr<u256,2>,2>, a
          // static-struct-leaf Arr<P,N>, ...) of a FULLY-STATIC outer calldata param. Re-encode it INLINE
          // (no [0x20] wrapper) directly from the leaf's calldata offset via the recursive codec, the SAME
          // encoder + validate rule the whole-param echo (echoStaticParam) uses: a VALUE-leaf fixed array
          // (bool[3], uint8[4], uint256[2][2]) MASKS dirty leaf words (solc's decode-to-memory cleans, no
          // revert), while a static-STRUCT-leaf fixed array (Arr<P,N>) VALIDATES each struct-field word.
          if (s.value.kind === 'cdPlaceReadAgg') {
            const off = this.lowerCdPlace(s.value.place, ctx, out);
            const leaf = (ty: JethType): JethType =>
              ty.kind === 'array' && ty.length !== undefined ? leaf(ty.element) : ty;
            const validate = !(s.value.type.kind === 'array' && isStaticValueType(leaf(s.value.type)));
            const ptr = this.fresh();
            out.push(`let ${ptr} := mload(0x40)`);
            const size = this.abiEncFromCd(s.value.type, off, ptr, validate, out);
            out.push(`mstore(0x40, add(${ptr}, ${size}))`);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          // a MEMORY-sourced NESTED value array bearing a DYNAMIC level (u256[][], Arr<u256[],N>,
          // u256[][][], ...), or a Residual-B aggregate-leaf array (P[] static struct / bytes[] /
          // string[]): resolve its memory image pointer, then ABI-encode it (relative offsets) via
          // abiEncFromMem. (A CALLDATA / STORAGE nested array keeps the echoParam / echoStorage
          // recursive encoder via the source-specific branches below; a pure-static nested array
          // Arr<Arr<u256,2>,2> is handled by the static-image / literal-head paths below.)
          {
            const memSourced =
              s.value.kind === 'arrayLit' ||
              s.value.kind === 'newArray' ||
              s.value.kind === 'memAggregate' ||
              (s.value.kind === 'arrayValue' &&
                (s.value.arr.base.kind === 'memArray' || s.value.arr.base.kind === 'memArrayExpr'));
            // Batch A: a MEMORY-sourced STATIC fixed-outer static-struct array (Arr<P,N>, Arr<Arr<P,N>,M>)
            // is a STATIC top-level return - solc encodes it INLINE (the N pointer-headed elements
            // flattened) with NO [0x20] offset wrapper. Encode the inline body via abiEncFromMem and return
            // that size. A memArrayExpr/memAggregate/arrayLit/newArray/arrayGet/aggFieldRead source lowers
            // to a memory image pointer. A STORAGE source (return this.pkgrid - an arrayValue with a
            // fixedArray base) keeps the storage-source encoder below (returnStorageValue), NOT this path.
            // POINTER-HEADED Arr<P,N> sources only (an aggFieldRead static-aggregate FIELD is inline and
            // is returned verbatim above, NOT here). An internal-call (call) Arr<P,N> return is also
            // pointer-headed but is handled by the verbatim exclusion + this branch via lowerExpr.
            const memFixedSrc =
              s.value.kind === 'arrayLit' ||
              s.value.kind === 'newArray' ||
              s.value.kind === 'memAggregate' ||
              s.value.kind === 'arrayGet' ||
              s.value.kind === 'call' ||
              (s.value.kind === 'arrayValue' &&
                (s.value.arr.base.kind === 'memArray' || s.value.arr.base.kind === 'memArrayExpr'));
            if (isStaticStructFixedLeafArray(s.value.type) && memFixedSrc) {
              const mp = this.nestedMemImagePtr(s.value, ctx, out);
              const dst = this.fresh();
              out.push(`let ${dst} := mload(0x40)`);
              const size = this.fresh();
              out.push(`let ${size} := ${this.abiEncFromMem(s.value.type, mp, dst, ctx, out)}`);
              out.push(`mstore(0x40, add(${dst}, ${size}))`);
              out.push(`return(${dst}, ${size})`);
              break;
            }
            const codecSourced =
              (isNestedValueArray(s.value.type) && isDynamicType(s.value.type)) ||
              isAggregateLeafArray(s.value.type) ||
              isDynBytesFixedLeafArray(s.value.type) ||
              // Lift #4: a FIXED-outer DYNAMIC-STRUCT array (Arr<In,N>) is dynamic top-level: the [0x20]
              // wrapper + abiEncFromMem's fixed-of-dynamic branch (per element -> abiEncDynStructFromMem).
              isDynStructFixedLeafArray(s.value.type) ||
              (isStaticStructAnyLeafArray(s.value.type) && isDynamicType(s.value.type)); // Arr<P,N>[] dynamic outer
            if (codecSourced && memSourced) {
              const mp = this.nestedMemImagePtr(s.value, ctx, out);
              const { ptr, size } = this.encodeNestedMemReturn(s.value.type, mp, ctx, out);
              out.push(`return(${ptr}, ${size})`);
              break;
            }
          }
          // a STATIC fixed-array LITERAL (return [a, b, c] typed Arr<T,N>, incl. nested static):
          // the ABI encoding is the N inline head words, with NO dynamic offset/length wrapper
          // (a dynamic-array return keeps the wrapper via encodeArrayReturn below). Writing the
          // literal at memory 0 and returning abiHeadWords*32 matches solc's uint256[N] layout.
          if (s.value.kind === 'arrayLit' && isStaticType(s.value.type)) {
            this.encodeArrayLitHead(s.value, 0, ctx, out);
            out.push(`return(0, ${abiHeadWords(s.value.type) * 32})`);
            break;
          }
          // a memory-array value produced by an expression (ternary `c ? xs : ys`, an incDec, or a
          // dynamic-array-returning internal call `return this.mk()`): lower to the [len][elems]
          // pointer, then encode the ABI [0x20][len][elems] return blob.
          if (
            s.value.kind === 'ternary' ||
            s.value.kind === 'incDec' ||
            (s.value.kind === 'call' && isDynamicType(s.value.type))
          ) {
            // FREEZE the pointer first: the encoder reads it multiple times, and a `call`
            // lowers to an inline `userfn_x(...)` that would otherwise be re-invoked per use.
            const p = this.fresh();
            out.push(`let ${p} := ${this.lowerExpr(s.value, ctx, out)}`);
            // An aggregate-leaf / nested-value image (P[] static-struct now pointer-headed, bytes[]/string[],
            // u256[][], P[][]) must go through the recursive codec (abiEncFromMem flattens a static-struct
            // element INLINE, follows a dynamic-element pointer) - the SAME encoder the abiDecode-return and
            // return-via-local paths use. encodeMemArrayReturn is only for a FLAT value array; using it on a
            // pointer-headed static-struct image would emit a wrong per-element offset table.
            const codecSourced =
              (isNestedValueArray(s.value.type) && isDynamicType(s.value.type)) ||
              isAggregateLeafArray(s.value.type) ||
              isDynBytesFixedLeafArray(s.value.type) ||
              isDynStructFixedLeafArray(s.value.type) || // Lift #4: Arr<In,N> via a ternary / internal call
              (isStaticStructAnyLeafArray(s.value.type) && isDynamicType(s.value.type));
            const { ptr, size } = codecSourced
              ? this.encodeNestedMemReturn(s.value.type, p, ctx, out)
              : this.encodeMemArrayReturn(p, out, s.value.type);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          // a whole dynamic calldata-array PARAM echo (`return a`) goes through the
          // general recursive encoder -> UNBOUNDED nesting depth. Other array sources
          // (storage, m[i] sub-arrays) keep the specialized encoder.
          if (
            s.value.kind === 'arrayValue' &&
            s.value.arr.base.kind === 'calldataArray' &&
            isDynamicType(s.value.type)
          ) {
            const { ptr, size } = this.echoParam(s.value.arr.base.name, s.value.type, ctx, out);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          // S5-B: `return o.xs` - a whole DYNAMIC-outer dyn-struct-ARRAY FIELD of a calldata dyn-struct
          // param (xs: St[], St a codec-supported dyn-struct-leaf). The DIRECT return mirrors the already-
          // matching two-step form `let ys: St[] = o.xs; return ys`: DEEP-COPY the field from its resolved
          // calldata header into a fresh pointer-headed memory image (aggArgToMemPtr's cdDynArrayField
          // branch -> cdFieldArrayHeader + abiDecFromCdToImage, Panic 0x41 cd->mem alloc cap), then ABI-
          // encode that image with the SAME encoder the memArray-local return uses (encodeNestedMemReturn:
          // [0x20] wrapper + abiEncFromMem). GATED to isAggregateLeafArray (the EXACT element-shape
          // predicate the let-bound localDecl gate uses): admits St with value / bytes/string / dynamic
          // value-array / static-struct-or-fixed-array fields, and REJECTS a NESTED-DYNAMIC-STRUCT-leaf
          // (St{inner:In}) or a struct-element-array field (St{ps:P[]}) - exactly the shapes
          // abiDecFromCdToImage cannot build and where the let-bound path itself rejects (JETH200/JETH072).
          // An unsupported element falls through to a clean JETH900 reject (byte-parallel to the let form),
          // never truncated/dangling bytes. Does NOT touch abi.encode(o.xs) (a separate path, already MATCHes).
          if (
            s.value.kind === 'arrayValue' &&
            s.value.arr.base.kind === 'cdDynArrayField' &&
            isDynamicType(s.value.type) &&
            isAggregateLeafArray(s.value.type)
          ) {
            const mp = this.aggArgToMemPtr(s.value, ctx, out);
            const { ptr, size } = this.encodeNestedMemReturn(s.value.type, mp, ctx, out);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          // W5C: `return s.xs` - a whole FIXED-outer dynamic-element FIELD of a calldata dyn-struct
          // param (xs: Arr<string,N>). Re-encode directly from the field's calldata tail (the N-word
          // offset table) via abiEncFromCd's fixed-of-dynamic branch, with the [0x20] top-level
          // wrapper (the type is dynamic). Mirrors echoCdFieldArray's whole-decode semantics.
          if (s.value.kind === 'arrayValue' && s.value.arr.base.kind === 'cdDynFixedDynField') {
            const b = s.value.arr.base;
            const hdr = this.cdFieldArrayHeader(b.place, ctx, out);
            out.push(`if gt(add(${hdr}, ${b.length * 32}), calldatasize()) { revert(0, 0) }`);
            const validate = !isValueLeafArray(s.value.type);
            const ptr = this.fresh();
            out.push(`let ${ptr} := mload(0x40)`);
            out.push(`mstore(${ptr}, 0x20)`);
            const size = this.fresh();
            out.push(`let ${size} := ${this.abiEncFromCd(s.value.type, hdr, `add(${ptr}, 0x20)`, validate, out, false)}`);
            out.push(`mstore(0x40, add(add(${ptr}, 0x20), ${size}))`);
            out.push(`return(${ptr}, add(0x20, ${size}))`);
            break;
          }
          // a whole STORAGE array whose element is DYNAMIC (string[], D[]) -> the
          // storage-source recursive encoder (unbounded nesting).
          if (s.value.kind === 'arrayValue' && s.value.arr.base.kind === 'stateArray' && isDynamicType(s.value.type)) {
            const { ptr, size } = this.echoStorage(s.value.arr.base.slot, s.value.type, out);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          // return this.fa (whole FIXED array): a static aggregate at a constant slot,
          // encoded inline by the storage-source recursive encoder.
          if (s.value.kind === 'arrayValue' && s.value.arr.base.kind === 'fixedArray') {
            const { ptr, size } = this.returnStorageValue(String(s.value.arr.base.baseSlot), s.value.type, out);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          // return this.dd[i] (a whole inner array of a storage nested array): encode from
          // the inner array's runtime length slot (placeArray) via the storage encoder.
          if (s.value.kind === 'arrayValue' && s.value.arr.base.kind === 'placeArray') {
            const ref = this.lowerArrayRef(s.value.arr, ctx, out);
            if (ref.src !== 'storage') throw new UnsupportedError('inner-array return requires a storage source');
            const { ptr, size } = this.returnStorageValue(ref.lenSlot, s.value.type, out);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          // return abi.decode(b, T) DIRECTLY for an array T (no intermediate local): materialize the
          // decoded image (the SAME lowerAbiDecode the `let a: T = abi.decode(b,T); return a;` local
          // form uses, via lowerArrayRef's abiDecode case), then encode it with the SAME encoder that
          // local form's return uses - encodeNestedMemReturn for an aggregate-leaf / nested-value image
          // (P[], bytes[]/string[], u256[][]), encodeMemArrayReturn for a flat value array. Byte-
          // identical to solc's direct-return decode (and to the local form, already verified).
          if (s.value.kind === 'abiDecode') {
            const mp = this.lowerAbiDecode(s.value.data, [s.value.type], ctx, out)[0]!;
            // Batch A: a STATIC fixed-outer static-struct array (Arr<P,N>) is encoded INLINE on return
            // (no [0x20] wrapper), via the recursive codec at the inline body.
            if (isStaticStructFixedLeafArray(s.value.type)) {
              const dst = this.fresh();
              out.push(`let ${dst} := mload(0x40)`);
              const size = this.fresh();
              out.push(`let ${size} := ${this.abiEncFromMem(s.value.type, mp, dst, ctx, out)}`);
              out.push(`return(${dst}, ${size})`);
              break;
            }
            // Fix 1a: a STATIC fixed-outer VALUE-leaf array (Arr<u256,N>, Arr<address,N>, nested static
            // Arr<Arr<u256,2>,3>, ...) reached DIRECTLY from an extCall / @interface-call return
            // (`return this.mk()` / `return IFace(a).mk()`, analyzed as abiDecode(extCall, T)): the decoded
            // image mp is ALREADY the flat inline ABI blob (abiHeadWords(T) inline words, NO [len] header).
            // solc returns it INLINE with no [0x20] offset wrapper - the SAME layout the let-bound form
            // (`let r: Arr<u256,N> = this.mk(); return r;`) emits via the verbatim static-image return path.
            // encodeMemArrayReturn would MISREAD the first element as a dynamic-array length (a wrong-bytes
            // miscompile), so return the flat image directly.
            if (isStaticType(s.value.type)) {
              out.push(`return(${mp}, ${abiHeadWords(s.value.type) * 32})`);
              break;
            }
            const codecSourced =
              (isNestedValueArray(s.value.type) && isDynamicType(s.value.type)) ||
              isAggregateLeafArray(s.value.type) ||
              isDynBytesFixedLeafArray(s.value.type) ||
              (isStaticStructAnyLeafArray(s.value.type) && isDynamicType(s.value.type));
            const { ptr, size } = codecSourced
              ? this.encodeNestedMemReturn(s.value.type, mp, ctx, out)
              : this.encodeMemArrayReturn(mp, out, s.value.type);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          const { ptr, size } = this.encodeArrayReturn(s.value, ctx, out);
          out.push(`return(${ptr}, ${size})`);
          break;
        }
        if (s.value.type.kind === 'struct') {
          if (isDynamicType(s.value.type)) {
            // a whole STORAGE dynamic struct (return this.d) -> storage-source encoder.
            if (s.value.kind === 'structValue') {
              const { ptr, size } = this.echoStorage(s.value.baseSlot, s.value.type, out);
              out.push(`return(${ptr}, ${size})`);
              break;
            }
            // a whole calldata dynamic-struct param echo (return s): the recursive
            // calldata encoder handles any field shape incl. dynamic-array fields
            // (unbounded), unlike the tuple-specific encoder.
            if (s.value.kind === 'cdDynStructValue' && !s.value.place) {
              const { ptr, size } = this.echoParam(s.value.param, s.value.type, ctx, out);
              out.push(`return(${ptr}, ${size})`);
              break;
            }
            // a whole nested-struct field of a dyn-struct param (return o.inner): re-encode
            // it as a standalone tuple from its resolved calldata tuple-start, reusing the
            // unbounded recursive calldata->memory encoder (abiEncFromCd), the same codec the
            // whole-param echo (echoParam) and the abi.encode path use - so any inner field
            // shape (value-array, bytes/string, nested struct) is handled byte-identically.
            if (s.value.kind === 'cdDynStructValue' && s.value.place) {
              const { ptr, size } = this.echoCdDynField(s.value.place, s.value.type, ctx, out);
              out.push(`return(${ptr}, ${size})`);
              break;
            }
            // a DYNAMIC struct return: [head 0x20][tuple head/tail at byte 0x20].
            const { ptr, size } = this.encodeDynStructReturn(s.value, ctx, out);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          // a whole STATIC nested-struct field of a dyn-struct param (return o.inner where
          // the inner struct is all-static): re-encode it flat (no head wrapper) from its
          // resolved calldata tuple-start via the recursive calldata->memory codec.
          if (s.value.kind === 'cdDynStructValue' && s.value.place) {
            const { ptr, size } = this.echoCdDynField(s.value.place, s.value.type, ctx, out);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          // S4: `return n.inner` - a whole STATIC nested-struct LEAF of a FULLY-STATIC outer calldata
          // param. Re-encode it INLINE (no [0x20] wrapper) directly from the leaf's calldata offset via
          // the recursive calldata->memory codec, the SAME encoder the whole-param echo (echoStaticParam)
          // uses. A whole STRUCT leaf ALWAYS validates (dirty narrow struct-field words EMPTY-revert,
          // matching solc's convert-to-memory) - so validate=true here.
          if (s.value.kind === 'cdPlaceReadAgg') {
            const off = this.lowerCdPlace(s.value.place, ctx, out);
            const ptr = this.fresh();
            out.push(`let ${ptr} := mload(0x40)`);
            const size = this.abiEncFromCd(s.value.type, off, ptr, true, out);
            out.push(`mstore(0x40, add(${ptr}, ${size}))`);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          // a STATIC struct read from storage (structValue) is encoded inline by the
          // recursive encoder, which flattens nested static structs / fixed-array fields
          // via structStorageLeaves. A constructed all-value struct (structNew) keeps the
          // flat field-by-field encoder (no storage source).
          if (s.value.kind === 'structValue') {
            const { ptr, size } = this.returnStorageValue(String(s.value.baseSlot), s.value.type, out);
            out.push(`return(${ptr}, ${size})`);
            break;
          }
          if (s.value.kind === 'structNew' && this.aggHasNonInlineField(s.value)) {
            // a constructed struct with a non-inline aggregate field: build the ABI image in FRESH
            // memory (the source materialization would clobber the memory-0 scratch), then return it.
            // W6A: the image is returned (ABI-copied out) immediately - a TRANSIENT capture context,
            // so an aliasable memory field source stays accepted (the copy is unobservable).
            const ptr = this.inTransientCapture(() => this.allocAggToMem(s.value as Expr & { kind: 'structNew' }, ctx, out));
            // W6C: a fixed ENUM-array field inherited from a raw-bound memory arg (Q(b, i)) is
            // range-checked on the way out (Panic 0x21, solc's encode validation).
            this.validateEnumMemArray(s.value.type, ptr, out);
            out.push(`return(${ptr}, ${abiHeadWords(s.value.type) * 32})`);
            break;
          }
          const size = this.encodeStructReturn(s.value, ctx, out);
          out.push(`return(0, ${size})`);
          break;
        }
        const v = this.lowerExpr(s.value, ctx, out);
        // single static value: the word is already the 32-byte ABI encoding.
        out.push(`mstore(0, ${v})`, 'return(0, 0x20)');
        break;
      }
      case 'localDecl': {
        const name = this.freshLocal(s.name);
        if (s.type.kind === 'struct' && isDynamicType(s.type) && s.init) {
          // a DYNAMIC-field struct memory local: build the pointer-headed image (value fields
          // inline, bytes/string fields a [len][data] pointer). Source: a constructor builds
          // fresh; a storage struct / calldata param is COPIED into a fresh image; another
          // dynamic-struct memory local ALIASES (pointer copy, matching Solidity references).
          out.push(`let ${name} := ${this.buildDynStructLocal(s.type, s.init, ctx, out)}`);
          this.ctxDeclare(ctx, s.name, name);
          break;
        }
        if ((s.type.kind === 'struct' || (s.type.kind === 'array' && s.type.length !== undefined)) && s.init) {
          // G9: a memory AGGREGATE local (struct or fixed array). A constructor / array literal
          // allocates a fresh ABI-unpacked image; a whole STORAGE aggregate (structValue, or an
          // arrayValue with a fixedArray base) or a calldata aggregate param (cdAggregateValue) is
          // COPIED into a fresh image; aliasing another memory aggregate (memAggregate) or a
          // struct-returning call copies the POINTER (matching Solidity memory references).
          if (
            s.type.kind === 'array' &&
            // isNestedValueWordArray also admits a nested FUNCREF-leaf array whose inner level is DYNAMIC
            // (Arr<((x)=>R)[],N>): the funcref inner is pointer-headed exactly like a u256[] inner.
            ((isNestedValueWordArray(s.type) && isDynamicType(s.type)) ||
              isStaticStructFixedLeafArray(s.type) ||
              isDynBytesFixedLeafArray(s.type) ||
              // Lift #4: a FIXED-outer DYNAMIC-STRUCT array local (Arr<In,N>): the same N-word
              // absolute-pointer table (no [len] header), each -> a per-element dyn-struct image.
              // An array literal builds it via buildNestedMemArrayLit (structNew element ->
              // allocDynStructToMem; a dyn-struct VALUE element -> buildDynStructLocal, aliasing).
              isDynStructFixedLeafArray(s.type))
          ) {
            // a FIXED array whose element is POINTER-HEADED: a DYNAMIC value-array (Arr<u256[],N>), or a
            // static struct / static-struct-leaf array (Batch A: Arr<P,N>, Arr<P,N>[], Arr<Arr<P,N>,M>).
            // The image is an N-word table of absolute pointers (no [len] header), NOT a flat inline image.
            // A literal builds it via the nested codec; any other source (alias / call) lowers to the table
            // pointer. (A FIXED array of a VALUE leaf - Arr<u256,N> - is NOT here: it stays inline below.)
            if (s.init.kind === 'arrayLit') out.push(`let ${name} := ${this.buildNestedMemArrayLit(s.init, ctx, out)}`);
            // #4 a FIXED-outer storage source (let row: Arr<P,N> = this.fa / this.m[k]): DEEP-COPY into a
            // fresh pointer-headed image via aggArgToMemPtr (which routes the fixedArray / mapStorageValue
            // base through abiDecFromStorageToImage's fixed-array branch). A memory alias / call result still
            // lowers to the existing table pointer below.
            // W5B shape 1: a CALLDATA fixed-of-dynamic PARAM source (let ys: Arr<string,N> = p) DEEP-COPIES
            // via the same aggArgToMemPtr route (abiDecFromCdToImage's fixed-of-dynamic branch at the
            // param's offset-table base), byte-identical to solc's `string[N] memory ys = p` copy.
            // W5C: a FIXED-outer dynamic-element FIELD of a calldata dyn-struct (let t: Arr<string,2>
            // = p.xs) DEEP-COPIES via the same aggArgToMemPtr route (cdFieldArrayHeader + table-fits +
            // abiDecFromCdToImage's fixed-of-dynamic branch, Panic 0x41 alloc cap).
            // W5C-mem: a FIXED-outer dynamic-element FIELD of a MEMORY dyn-struct (let ys: Arr<string,N>
            // = d.tags, d a memory-built local / internal memory param / nested sub-struct field
            // v.t.tags / P[]-element field xs[i].tags) resolves to an arrayValue with a memArrayExpr
            // base wrapping the head-word LOAD of the field image pointer. aggArgToMemPtr ALIASES it
            // (returns lowerExpr(base.expr) = that pointer verbatim), so ys points at d.tags's image -
            // a memory-to-memory reference, byte-identical to solc's `string[N] memory ys = d.tags`
            // (mutating ys[i] writes through to d.tags[i] and vice versa). This is the SAME field
            // image pointer the working `return d.tags` / `abi.encode(d.tags)` / internal-arg paths use.
            else if (
              (s.init.kind === 'arrayValue' &&
                (s.init.arr.base.kind === 'fixedArray' ||
                  s.init.arr.base.kind === 'stateArray' ||
                  s.init.arr.base.kind === 'mapArray' ||
                  s.init.arr.base.kind === 'placeArray' ||
                  s.init.arr.base.kind === 'calldataArray' ||
                  s.init.arr.base.kind === 'cdDynFixedDynField' ||
                  s.init.arr.base.kind === 'memArrayExpr')) ||
              s.init.kind === 'mapStorageValue'
            )
              out.push(`let ${name} := ${this.aggArgToMemPtr(s.init, ctx, out)}`);
            else out.push(`let ${name} := ${this.lowerExpr(s.init, ctx, out)}`);
          } else if (s.init.kind === 'structNew' || s.init.kind === 'arrayLit') {
            out.push(`let ${name} := ${this.allocAggToMem(s.init, ctx, out)}`);
          } else if (s.init.kind === 'structValue') {
            out.push(`let ${name} := ${this.allocAggFromStorage(s.init.type, String(s.init.baseSlot), out)}`);
          } else if (s.init.kind === 'arrayValue' && s.init.arr.base.kind === 'fixedArray') {
            out.push(`let ${name} := ${this.allocAggFromStorage(s.init.type, String(s.init.arr.base.baseSlot), out)}`);
          } else if (s.init.kind === 'mapStorageValue') {
            // a storage mapping struct value (this.m[k]) COPIED into a fresh image
            out.push(
              `let ${name} := ${this.allocAggFromStorage(s.init.type, this.mappingSlot(s.init.baseSlot, s.init.keys, ctx, out), out)}`,
            );
          } else if (s.init.kind === 'structArrayElem') {
            // a storage struct-array element (this.arr[i]) COPIED into a fresh image (also the for-of desugar)
            out.push(
              `let ${name} := ${this.allocAggFromStorage(s.init.type, this.structArrayElemSlot(s.init.arr, s.init.index, ctx, out), out)}`,
            );
          } else if (s.init.kind === 'cdAggregateValue') {
            out.push(`let ${name} := ${this.allocAggFromCalldata(s.init.param, s.init.type, ctx, out, true)}`);
          } else if (s.init.kind === 'cdStructArrayElem') {
            // a STATIC struct element of a calldata struct array (let p: P = ps[i]): copy the
            // element's contiguous calldata head into a fresh static-aggregate memory image (the
            // same abiEncFromCd transcode the whole-param copy uses, at the element base).
            const eb = this.cdArrayElemBase(s.init.arr, s.init.index, s.init.type, ctx, out);
            out.push(`let ${name} := ${this.allocAggFromCalldataBase(s.init.type, eb, out)}`);
          } else if (s.init.kind === 'abiDecode') {
            // a static fixed array Arr<T,N> from abi.decode: the decoded flat ABI image is the local.
            out.push(`let ${name} := ${this.aggArgToMemPtr(s.init, ctx, out)}`);
          } else if (s.init.kind === 'arrayGet') {
            // a static-struct ELEMENT of a now-POINTER-HEADED memory struct array (let p: P = xs[i]):
            // aggToMemPtr returns the element slot's absolute pointer, so p ALIASES the element image
            // (no copy) - byte-identical to solc (mutating p writes through; re-pointing xs[i] leaves p).
            out.push(`let ${name} := ${this.aggToMemPtr(s.init, ctx, out)}`);
          } else if (s.init.kind === 'cdAggArrayElem') {
            // a FIXED-inner VALUE-leaf element of a calldata array-of-array (let row: Arr<u256,N> = xs[i]):
            // DEEP-COPY the element's calldata head into a fresh memory image via the calldata->memory codec
            // (aggArgToMemPtr's cdAggArrayElem branch resolves the element base + materializes).
            out.push(`let ${name} := ${this.aggArgToMemPtr(s.init, ctx, out)}`);
          } else if (s.init.kind === 'arrayValue' && s.init.arr.base.kind === 'memArrayExpr') {
            // a FIXED VALUE-array ELEMENT of a MEMORY outer array (let row: Arr<u256,N> = xs[i], xs:
            // Arr<u256,N>[]): aggArgToMemPtr lowers the memArrayExpr's inner arrayGet to the element's
            // absolute pointer, so row ALIASES the element image (no copy) - a later row[j] = v writes
            // through to xs[i][j], byte-identical to solc memory references.
            out.push(`let ${name} := ${this.aggArgToMemPtr(s.init, ctx, out)}`);
          } else {
            out.push(`let ${name} := ${this.lowerExpr(s.init, ctx, out)}`);
          }
          this.ctxDeclare(ctx, s.name, name);
          break;
        }
        if (isBytesLike(s.type) && s.init) {
          // G9: a bytes/string memory local. Materialize the init source into a memory
          // [len][data] blob; the register holds the pointer. toMemory COPIES a calldata /
          // storage / literal source, and aliases a memory source (matching Solidity).
          const { mp } = this.toMemory(this.lowerDynamic(s.init, ctx, out), out);
          out.push(`let ${name} := ${mp}`);
          this.ctxDeclare(ctx, s.name, name);
          break;
        }
        if (s.type.kind === 'array' && s.type.length === undefined && s.init) {
          // G9: a DYNAMIC value-array memory local (let a: u256[] = p / xs / this.arr). The
          // register holds a [len][elems] pointer: aggArgToMemPtr ALIASES a memory source
          // (pointer copy, matching Solidity references) and COPIES a calldata/storage/literal
          // source into a fresh image (a calldata value array MASKS dirty elements, like solc).
          out.push(`let ${name} := ${this.aggArgToMemPtr(s.init, ctx, out)}`);
          this.ctxDeclare(ctx, s.name, name);
          break;
        }
        if (s.init) {
          const v = this.lowerExpr(s.init, ctx, out);
          out.push(`let ${name} := ${v}`);
        } else {
          out.push(`let ${name} := 0`); // matches Solidity zero-default
        }
        this.ctxDeclare(ctx, s.name, name);
        break;
      }
      case 'assign': {
        if (s.target.kind === 'aggFieldStore' && !isStaticValueType(s.target.type) && s.target.type.kind !== 'funcref') {
          // xs[i].q = Q(..) / xs[i].pre = [..]: a whole STATIC AGGREGATE field of a memory-array struct
          // element. Copy the constructed/source image into the field's sub-image (the same pointer the
          // read uses, layout-agnostic). solc evaluates the RHS before the LHS, so materialize src first.
          // FIX C (funcref): a funcref LEAF (h.fs[i] = this.g) is a single value WORD, not an aggregate,
          // so it is EXCLUDED here and falls through to the scalar aggFieldStore path (an mstore of its id).
          const src = this.aggToMemPtr(s.value, ctx, out);
          const dst = this.aggFieldPtr(s.target.base, s.target.wordOffset, s.target.runSteps, ctx, out);
          const ew = abiHeadWords(s.target.type) * 32;
          for (let k = 0; k < ew / 32; k++) out.push(`mstore(add(${dst}, ${k * 32}), mload(add(${src}, ${k * 32})))`);
          break;
        }
        if (s.target.kind === 'state' && s.target.type.kind === 'struct') {
          // whole-struct write: a constructed value (structNew), a memory/calldata struct
          // (this.d = m / this.d = calldataParam), or a storage-to-storage copy (this.d = this.e).
          this.storeStructTo(s.target.type, s.value, String(s.target.slot), ctx, out);
          break;
        }
        if (s.target.kind === 'mapping' && s.target.type.kind === 'struct') {
          // this.m[k] = <struct>: write the constructed/copied struct into the runtime
          // keccak(key.base) mapping slot (the prepared store / copyStruct clear dynamic-field
          // tails per field, byte-identical to solc). W7B (RHS-first): solc evaluates the RHS
          // completely BEFORE the mapping key (P4/P29 - a key reading state mutated by a ctor
          // arg sees the post-arg value), so prepare the value, then resolve the key.
          const prep = this.prepareStructStore(s.target.type, s.value, ctx, out);
          const dst = this.mappingSlot(s.target.baseSlot, s.target.keys, ctx, out);
          this.emitPreparedStructStore(s.target.type, prep, dst, out);
          break;
        }
        // whole DYNAMIC-array assignment into storage: this.a = this.b (storage source) or
        // this.a = xs / this.m[k] = xs (a MEMORY value-array source), or a struct field
        // this.s.arr = xs (a storage place at the field's length slot). copyArrayValueIntoStorage
        // deep-copies (resize + element copy + tail clear) from either source.
        if (
          (s.target.kind === 'state' || s.target.kind === 'mapping' || s.target.kind === 'place') &&
          s.target.type.kind === 'array' &&
          s.target.type.length === undefined
        ) {
          const dstLenSlot =
            s.target.kind === 'mapping'
              ? this.mappingSlot(s.target.baseSlot, s.target.keys, ctx, out)
              : s.target.kind === 'place'
                ? this.lowerPlace(s.target.path, ctx, out).slot
                : String(s.target.slot);
          this.copyArrayValueIntoStorage(s.target.type.element, s.value, dstLenSlot, ctx, out);
          break;
        }
        // whole FIXED-array assignment into storage: this.g = this.src (storage source) or
        // this.g = [a, b, c] (array literal). Static-element arrays copy their slot footprint
        // verbatim; dynamic-element fixed arrays deep-copy per element.
        if (
          (s.target.kind === 'state' || s.target.kind === 'place' || s.target.kind === 'mapping') &&
          s.target.type.kind === 'array' &&
          s.target.type.length !== undefined
        ) {
          // W5A (RHS-first): solc materializes a MEMORY-source RHS (an array literal / a memory or
          // calldata aggregate) BEFORE resolving the target location (a place path's index bounds-check,
          // a mapping key), so a side-effecting or reverting literal element runs FIRST - revert data and
          // interleaved state reads match solc. A pure-value static literal builds its flat image via
          // allocAggToMem and transcodes through storeStaticAggFromMem (same final slots as the direct
          // writeArrayLit, packed elements included). A STRUCT-element literal stays on the writeArrayLit
          // path below (its memory form is pointer-headed, not a flat transcode source); a storage source
          // is a reference (no side effects), so target-first is unobservable for both.
          const tt = s.target.type;
          // W6A: the materialized RHS image is immediately deep-copied into storage (a TRANSIENT
          // capture context) - an aliasable memory element source inside a literal stays accepted.
          const memSrc: string | undefined = this.inTransientCapture(() =>
            s.value.kind === 'arrayLit'
              ? isDynLeafFixedArray(tt)
                ? this.buildNestedMemArrayLit(s.value as Expr & { kind: 'arrayLit' }, ctx, out)
                : isStaticType(tt) && isInlineValueWordElem(tt.element)
                  ? this.allocAggToMem(s.value as Expr & { kind: 'arrayLit' }, ctx, out)
                  : undefined
              : s.value.kind === 'memAggregate' || s.value.kind === 'cdAggregateValue'
                ? this.aggToMemPtr(s.value, ctx, out)
                : undefined,
          );
          const dstBase =
            s.target.kind === 'state'
              ? String(s.target.slot)
              : s.target.kind === 'mapping'
                ? this.mappingSlot(s.target.baseSlot, s.target.keys, ctx, out)
                : this.lowerPlace(s.target.path, ctx, out).slot;
          if (memSrc !== undefined) {
            if (isDynLeafFixedArray(tt)) this.storeDynLeafFixedArrayFromMem(tt, memSrc, dstBase, out);
            else this.storeStaticAggFromMem(tt, memSrc, dstBase, out);
            break;
          }
          // NF-1 (memSrc above): a whole store into a FIXED-outer array whose leaf is dynamic
          // (Arr<string,N> / Arr<bytes,N> / nested Arr<Arr<string,N>,M> / Arr<u256[],N>) transcodes the
          // pointer-headed memory image element-by-element into the N consecutive base slots through the
          // SAME codec the corresponding single-element store uses (storeDynamic / copyMemArrayIntoStorage /
          // copyMemAggArrayIntoStorage), each of which overwrite-clears the dst element's old tail on
          // shrink - byte-identical to solc. A pure-value static source transcodes its flat ABI-unpacked
          // image into packed storage (storeStaticAggFromMem), exactly like a whole memory struct assign.
          // Remaining here: a STRUCT-element literal (writeArrayLit constructs in place) and a
          // storage->storage source (copyFixedArray, per-element overwrite-clear).
          if (s.value.kind === 'arrayLit') {
            this.writeArrayLit(s.value, dstBase, ctx, out);
          } else {
            this.copyFixedArray(s.target.type, this.fixedArraySrcBase(s.value, ctx, out), dstBase, out);
          }
          break;
        }
        if (s.target.kind === 'place' && s.target.type.kind === 'struct') {
          // this.o.inner = <struct> (whole nested-struct field). W7B (RHS-first): solc evaluates
          // the RHS completely BEFORE resolving the path (its index bounds checks / key reads),
          // so prepare the value, then fold the path to the field slot, then store.
          const prep = this.prepareStructStore(s.target.type, s.value, ctx, out);
          const p = this.lowerPlace(s.target.path, ctx, out);
          this.emitPreparedStructStore(s.target.type, prep, p.slot, out);
          break;
        }
        if (s.target.kind === 'place') {
          // solc evaluates the RHS before the LHS location (incl every index/key in the path). Bind the
          // value FIRST so a side-effecting path index (aa[inc()][inc()] = inc()) does not run ahead of
          // a side-effecting RHS; the optimizer collapses the temp for pure operands (byte-identical).
          const value = this.fresh();
          out.push(`let ${value} := ${this.lowerExpr(s.value, ctx, out)}`);
          const p = this.lowerPlace(s.target.path, ctx, out);
          // a packed element with a RUNTIME byte offset uses packedStore; otherwise the
          // constant-offset storeState (also covers a literal packed index).
          if (p.byteShift !== undefined) this.packedStore(s.target.type, p.slot, p.byteShift, value, out);
          else for (const l of this.storeState(s.target.type, p.slot, p.offset, value)) out.push(l);
          break;
        }
        if (
          s.target.kind === 'memField' ||
          s.target.kind === 'memElem' ||
          (s.target.kind === 'memDynNestedFieldStore' && !s.target.deref)
        ) {
          // p.x = v / a[i] = v / v.t.n = v on a memory aggregate local (value leaf): bounds-checked memory
          // store. Bind the RHS FIRST (solc evaluates it before the LHS index); the optimizer collapses the
          // temp for pure operands, so the bytecode is unchanged for the common case.
          const value = this.fresh();
          out.push(`let ${value} := ${this.lowerExpr(s.value, ctx, out)}`);
          this.lowerAssignValue(s.target, value, ctx, out);
          break;
        }
        if (s.target.kind === 'byteIndexStore') {
          // this.b[i] = <bytes1>: bounds-checked read-modify-write of byte i in a storage `bytes`.
          // The bytes location (direct var / struct field / mapping value / array elem) resolves to
          // its slot exactly like the whole-value assignment.
          // solc evaluates the RHS byte value FIRST, then the location and the index. Bind v first.
          const v = this.fresh();
          out.push(`let ${v} := ${this.lowerExpr(s.value, ctx, out)}`);
          const bslot = this.bytesLocSlot(s.target.loc, ctx, out);
          const i = this.fresh();
          out.push(`let ${i} := ${this.lowerExpr(s.target.index, ctx, out)}`);
          out.push(`${this.strByteSet()}(${bslot}, ${i}, ${v})`);
          break;
        }
        if (s.target.kind === 'memByteIndexStore') {
          // d[i] = <bytes1> on a MEMORY `bytes` value: bounds-checked in-place mstore8.
          // solc evaluates the RHS byte value FIRST, then the base location and the index.
          const v = this.fresh();
          out.push(`let ${v} := ${this.lowerExpr(s.value, ctx, out)}`);
          const ref = this.lowerDynamic(s.target.base, ctx, out);
          if (ref.src !== 'memory') throw new UnsupportedError('memByteIndexStore base must be a memory bytes value');
          const len = this.fresh();
          out.push(`let ${len} := mload(${ref.ptr})`);
          const i = this.fresh();
          out.push(`let ${i} := ${this.lowerExpr(s.target.index, ctx, out)}`);
          out.push(`if iszero(lt(${i}, ${len})) { ${this.panic()}(0x32) }`);
          // the RHS bytes1 is left-aligned; its byte lives at byte index 0 (the MSB).
          out.push(`mstore8(add(${ref.ptr}, add(0x20, ${i})), byte(0, ${v}))`);
          break;
        }
        if (s.target.kind === 'memDynField') {
          // d.s = <bytes/string> OR d.xs = <array> on a dynamic-field struct memory local: materialize the
          // value (a bytes/string [len][data] blob, or a value-array [len][elems] / leaf-array B4 image),
          // then re-point the field's head word at it (Solidity memory-struct field assignment is a reference
          // re-point), exactly like the aggDynFieldStore (xs[i].field = ...) path just below.
          const srcRaw = isBytesLike(s.target.type)
            ? this.toMemory(this.lowerDynamic(s.value, ctx, out), out).mp
            : this.aggArgToMemPtr(s.value, ctx, out);
          const head = this.ctxLookup(ctx, s.target.local);
          out.push(`mstore(${s.target.wordOffset === 0 ? head : `add(${head}, ${s.target.wordOffset * 32})`}, ${srcRaw})`);
          break;
        }
        if (s.target.kind === 'memDynNestedFieldStore' && s.target.deref) {
          // v.t.s = <bytes/string> / v.t.arr = <array> on a NESTED dynamic-struct field: materialize the RHS
          // blob/array FIRST (solc evaluates the RHS before the LHS location), then deref the chain to the
          // inner image and re-point the field's head word at it (a reference re-point, like the single-level
          // memDynField store above).
          const srcRaw = isBytesLike(s.target.type)
            ? this.toMemory(this.lowerDynamic(s.value, ctx, out), out).mp
            : this.aggArgToMemPtr(s.value, ctx, out);
          const src = this.fresh();
          out.push(`let ${src} := ${srcRaw}`);
          const inner = this.nestedInnerPtr(s.target.local, s.target.derefWords, ctx, out);
          out.push(`mstore(${s.target.finalWord === 0 ? inner : `add(${inner}, ${s.target.finalWord * 32})`}, ${src})`);
          break;
        }
        if (s.target.kind === 'aggDynFieldStore') {
          // Residual B3: xs[i].s = <bytes/string> or xs[i].arr = <u256[]> on a memory P[] dyn-struct
          // element: re-point the dyn-struct image head word at a freshly-materialized blob/array pointer
          // (a reference assignment, like solc). RHS materialized FIRST (solc evaluates it before the LHS
          // location, incl the element index); then resolve the element image head word and store.
          const srcRaw = isBytesLike(s.target.type)
            ? this.toMemory(this.lowerDynamic(s.value, ctx, out), out).mp
            : this.aggArgToMemPtr(s.value, ctx, out);
          const src = this.fresh();
          out.push(`let ${src} := ${srcRaw}`);
          const head = this.aggToMemPtr(s.target.base, ctx, out);
          out.push(`mstore(${s.target.wordOffset === 0 ? head : `add(${head}, ${s.target.wordOffset * 32})`}, ${src})`);
          break;
        }
        if (s.target.kind === 'dynState') {
          const ref = this.lowerDynamic(s.value, ctx, out);
          this.storeDynamic(String(s.target.slot), ref, out);
          break;
        }
        if (s.target.kind === 'mapDynState') {
          // this.m[k] = <bytes/string>: materialize the RHS value FIRST (solc evaluates the RHS before
          // the LHS key - a side-effecting key must not run ahead of it), then compute the runtime
          // mapping slot and overwrite-store (storeDynamic clears the old tail).
          const ref = this.lowerDynamic(s.value, ctx, out);
          const slot = this.mappingSlot(s.target.baseSlot, s.target.keys, ctx, out);
          this.storeDynamic(slot, ref, out);
          break;
        }
        if (s.target.kind === 'strArrayElem') {
          if (s.target.arr.base.kind === 'memArray' || s.target.arr.base.kind === 'memArrayExpr') {
            // bs[i] = <bytes/string> on a MEMORY bytes[]/string[]: materialize the RHS to a [len][data]
            // blob FIRST (alias if already memory), bounds-check i, then re-point the element pointer word
            // (a reference assignment, like solc's memory bytes[] element store). RHS-first eval order.
            const { mp } = this.toMemory(this.lowerDynamic(s.value, ctx, out), out);
            const ref = this.lowerArrayRef(s.target.arr, ctx, out);
            if (ref.src !== 'memory') throw new UnsupportedError('memory bytes[]/string[] element write requires a memory array');
            const idx = this.fresh();
            out.push(`let ${idx} := ${this.lowerExpr(s.target.index, ctx, out)}`);
            // a DYNAMIC outer (string[]/bytes[]) has a [len] header (bound = mload(ptr), data at ptr+0x20);
            // Edge D: a FIXED outer (Arr<string,N>/Arr<bytes,N>, ref.fixedLen) bounds against the constant N
            // and has NO header (the N pointer words start at ptr). Mirror lowerArrayGet's fixedLen handling.
            const bound = ref.fixedLen !== undefined ? String(ref.fixedLen) : `mload(${ref.ptr})`;
            out.push(`if iszero(lt(${idx}, ${bound})) { ${this.panic()}(0x32) }`);
            const dataBase = ref.fixedLen !== undefined ? `${ref.ptr}` : `add(${ref.ptr}, 0x20)`;
            out.push(`mstore(add(${dataBase}, mul(${idx}, 0x20)), ${mp})`);
            break;
          }
          // this.ss[i] = <bytes/string>: materialize the RHS FIRST (solc evaluates the RHS before the
          // LHS index), then bounds-check i and overwrite the element header at keccak(lenSlot)+i
          // (storeStrMem clears the old tail).
          const ref = this.lowerDynamic(s.value, ctx, out);
          const slot = this.strArrayElemSlot(s.target.arr, s.target.index, ctx, out);
          this.storeDynamic(slot, ref, out);
          break;
        }
        if (s.target.kind === 'dynPlace') {
          // this.d.s = <bytes/string> (storage dynamic-struct field): materialize the RHS FIRST (solc
          // evaluates the RHS before the LHS path's index/key), then fold the path to the field's slot
          // (struct base + field slot, index/key bound-checks applied) and overwrite-store the value
          // (storeStrMem clears the old tail, identical to solc).
          const ref = this.lowerDynamic(s.value, ctx, out);
          const p = this.lowerPlace(s.target.path, ctx, out);
          this.storeDynamic(p.slot, ref, out);
          break;
        }
        if (s.target.kind === 'arrayElem' && s.target.type.kind === 'array') {
          // A whole-inner-array element write on a NESTED MEMORY array local (m[i] = [...]): not a
          // storage place. The element is either an absolute pointer word (a DYNAMIC inner array) or an
          // inline static sub-block (a STATIC inner array); mirror the read side (lowerArrayGet memory
          // branch). solc evaluates the RHS before the LHS location, so materialize the RHS first.
          if (s.target.arr.base.kind === 'memArray' || s.target.arr.base.kind === 'memArrayExpr') {
            this.writeNestedMemArrayElem(s.target, s.value, ctx, out);
            break;
          }
          if (s.target.type.length !== undefined) {
            // this.dd[i] = <array> (a whole FIXED inner-array element): copy the aggregate into the
            // element BASE slot (base + i*storageSlotCount), like the whole-array assign.
            // W5A: a MEMORY / CALLDATA source and a dyn-leaf element type route through the SAME codecs
            // the whole-array assign uses (storeDynLeafFixedArrayFromMem transcodes the pointer-headed
            // image with per-element overwrite-clear; storeStaticAggFromMem transcodes a flat static
            // image), byte-identical to solc's `g3[i] = a`. RHS-first: the memory source (incl. a
            // side-effecting/reverting literal element) is materialized BEFORE the element slot's index
            // bounds-check, matching solc's evaluation order (revert data included). A STRUCT-element
            // literal stays on writeArrayLit; a storage source stays on copyFixedArray.
            const et = s.target.type;
            const memSrc: string | undefined =
              s.value.kind === 'arrayLit'
                ? isDynLeafFixedArray(et)
                  ? this.buildNestedMemArrayLit(s.value, ctx, out)
                  : isStaticType(et) && isInlineValueWordElem(et.element)
                    ? this.allocAggToMem(s.value, ctx, out)
                    : undefined
                : s.value.kind === 'memAggregate' || s.value.kind === 'cdAggregateValue'
                  ? this.aggToMemPtr(s.value, ctx, out)
                  : undefined;
            const elemBase = this.structArrayElemSlot(s.target.arr, s.target.index, ctx, out);
            if (memSrc !== undefined) {
              if (isDynLeafFixedArray(et)) this.storeDynLeafFixedArrayFromMem(et, memSrc, elemBase, out);
              else this.storeStaticAggFromMem(et, memSrc, elemBase, out);
            } else if (s.value.kind === 'arrayLit') this.writeArrayLit(s.value, elemBase, ctx, out);
            else this.copyFixedArray(s.target.type, this.fixedArraySrcBase(s.value, ctx, out), elemBase, out);
            break;
          }
          // this.dd[i] = <array> (a whole DYNAMIC inner array element): the element slot
          // is the inner array's length slot (data + i*1); deep-copy the value in
          // (overwrite-clearing the old inner array).
          const innerLenSlot = this.structArrayElemSlot(s.target.arr, s.target.index, ctx, out);
          this.copyArrayValueIntoStorage(s.target.type.element, s.value, innerLenSlot, ctx, out);
          break;
        }
        if (s.target.kind === 'arrayElem' && s.target.type.kind === 'struct') {
          if (
            (s.target.arr.base.kind === 'memArray' || s.target.arr.base.kind === 'memArrayExpr') &&
            isDynamicType(s.target.type)
          ) {
            // Residual B3: xs[i] = P(..) on a MEMORY P[] dyn-struct array: build a fresh pointer-headed
            // dyn-struct image from the source (constructor / alias / storage copy), then RE-POINT the
            // element's pointer word at it (a reference assignment, like solc). RHS materialized FIRST,
            // then the element slot (bounds-checked) is resolved.
            const img = this.fresh();
            out.push(`let ${img} := ${this.buildDynStructLocal(s.target.type as JethType & { kind: 'struct' }, s.value, ctx, out)}`);
            const ref = this.lowerArrayRef(s.target.arr, ctx, out);
            if (ref.src !== 'memory') throw new UnsupportedError('B3 element write requires a memory array');
            const idx = this.fresh();
            out.push(`let ${idx} := ${this.lowerExpr(s.target.index, ctx, out)}`);
            const bound = ref.fixedLen !== undefined ? String(ref.fixedLen) : `mload(${ref.ptr})`;
            out.push(`if iszero(lt(${idx}, ${bound})) { ${this.panic()}(0x32) }`);
            const dataBase = ref.fixedLen !== undefined ? ref.ptr! : `add(${ref.ptr}, 0x20)`;
            out.push(`mstore(add(${dataBase}, mul(${idx}, 0x20)), ${img})`);
            break;
          }
          if (s.target.arr.base.kind === 'memArray' || s.target.arr.base.kind === 'memArrayExpr') {
            // Cat B: xs[i] = <struct> on a MEMORY static-struct array, now POINTER-HEADED (each slot is
            // an absolute pointer to a per-element image). RE-POINT the element's pointer word at the RHS
            // image (a reference assignment, exactly like solc and like the B3 dyn-struct branch above):
            // a constructor xs[i] = P(..) materializes a FRESH image; a reference xs[i] = xs[j] / = ref
            // ALIASES by storing the source's image pointer. aggToMemPtr does both (fresh alloc for a
            // constructor / storage / calldata copy; the source pointer for a memory ref). solc evaluates
            // the RHS before the LHS location, so materialize the source FIRST, then resolve the element
            // slot (bound-checks i).
            const img = this.aggToMemPtr(s.value, ctx, out);
            const ref = this.lowerArrayRef(s.target.arr, ctx, out);
            if (ref.src !== 'memory') throw new UnsupportedError('B1 element write requires a memory array');
            const idx = this.fresh();
            out.push(`let ${idx} := ${this.lowerExpr(s.target.index, ctx, out)}`);
            const bound = ref.fixedLen !== undefined ? String(ref.fixedLen) : `mload(${ref.ptr})`;
            out.push(`if iszero(lt(${idx}, ${bound})) { ${this.panic()}(0x32) }`);
            const dataBase = ref.fixedLen !== undefined ? ref.ptr! : `add(${ref.ptr}, 0x20)`;
            out.push(`mstore(add(${dataBase}, mul(${idx}, 0x20)), ${img})`);
            break;
          }
          // this.recs[i] = <struct>: write the constructed/copied struct into the
          // bounds-checked storage element slot (the prepared store / copyStruct clear
          // dynamic-field tails per field, byte-identical to solc). W7B (RHS-first): solc
          // evaluates the RHS completely BEFORE the index + bounds check (P6/P30 - an index
          // reading state mutated by a ctor arg sees the post-arg value), so prepare the
          // value, then resolve the element slot.
          const prep = this.prepareStructStore(s.target.type, s.value, ctx, out);
          const elemSlot = this.structArrayElemSlot(s.target.arr, s.target.index, ctx, out);
          this.emitPreparedStructStore(s.target.type, prep, elemSlot, out);
          break;
        }
        if (s.target.kind === 'arrayElem') {
          // solc evaluates the RHS before the LHS location (incl its index). Bind the value FIRST so
          // a side-effecting index (a[inc()] = inc()) does not run ahead of a side-effecting RHS; for
          // pure operands the solc Yul optimizer collapses the temp, so the bytecode is unchanged.
          const value = this.fresh();
          out.push(`let ${value} := ${this.lowerExpr(s.value, ctx, out)}`);
          const ref = this.lowerArrayRef(s.target.arr, ctx, out); // storage/fixed (analyzer rejects calldata)
          const idx = this.fresh();
          out.push(`let ${idx} := ${this.lowerExpr(s.target.index, ctx, out)}`);
          if (ref.src === 'fixed') {
            out.push(`if iszero(lt(${idx}, ${ref.length})) { ${this.panic()}(0x32) }`);
            this.arrayElemStore(s.target.type, String(ref.baseSlot), idx, value, out);
          } else if (ref.src === 'storage') {
            out.push(`if iszero(lt(${idx}, sload(${ref.lenSlot}))) { ${this.panic()}(0x32) }`);
            const data = this.arrayDataSlot(ref.lenSlot, out);
            this.arrayElemStore(s.target.type, data, idx, value, out);
          } else if (ref.src === 'memory') {
            // memory value-element array write (one word). A DYNAMIC outer T[] has a [len] header word
            // (bound mload(ptr), data at ptr+0x20); a FIXED inner Arr<T,N> (ref.fixedLen, e.g. m[i] of an
            // Arr<T,N>[]) is HEADER-LESS - bound vs the constant N, data at ptr. Mirrors the read path so
            // the write lands at base+idx*0x20 exactly like solc (the old mload/+0x20 form read element-0
            // as a phantom length: a spurious Panic when it is 0, a 1-word skew when it is non-zero).
            const bound = ref.fixedLen !== undefined ? String(ref.fixedLen) : `mload(${ref.ptr})`;
            out.push(`if iszero(lt(${idx}, ${bound})) { ${this.panic()}(0x32) }`);
            const dataBase = ref.fixedLen !== undefined ? ref.ptr : `add(${ref.ptr}, 0x20)`;
            out.push(`mstore(add(${dataBase}, mul(${idx}, 0x20)), ${value})`);
          } else {
            throw new UnsupportedError('cannot assign to a calldata array element');
          }
          break;
        }
        if (s.target.kind === 'local' && s.target.type.kind === 'struct') {
          // Re-point a struct MEMORY local by assignment: `s = P(...)` / `s = this.p` / `s = other`.
          // Solidity rebinds the local to a fresh image - a constructed struct (structNew) builds
          // fresh; a STORAGE struct (structValue / mapStorageValue / structArrayElem / placeRead) or a
          // CALLDATA struct param (cdAggregateValue) is COPIED into fresh memory (a later `s.f = ...`
          // must NOT alias the source); another memory struct (memAggregate) or a struct-returning
          // call ALIASES the pointer (a memory reference). A DYNAMIC-field struct uses the
          // pointer-headed image builder, a static struct the flat ABI-image materializer - exactly
          // the helpers the `let s: P = <src>` DECLARATION path uses, so the image is byte-identical.
          const reg = this.ctxLookup(ctx, s.target.varName);
          const ptr = isDynamicType(s.target.type)
            ? this.buildDynStructLocal(s.target.type, s.value, ctx, out)
            : this.aggToMemPtr(s.value, ctx, out);
          out.push(`${reg} := ${ptr}`);
          break;
        }
        if (s.target.kind === 'local' && isBytesLike(s.target.type)) {
          // Re-point a bytes/string MEMORY local (or an @internal/@private bytes/string param, both held
          // as a [len][data] memory pointer): `d = bytes("x")` / `s = "x"`. Materialize the RHS into a
          // memory blob (toMemory aliases an already-in-memory value, COPIES a calldata/storage source)
          // and rebind the register at it - Solidity's `bytes memory` reference re-point, byte-identical.
          // An @external (calldata, read-only) param never reaches here (the analyzer rejects it cleanly).
          const { mp } = this.toMemory(this.lowerDynamic(s.value, ctx, out), out);
          out.push(`${this.ctxLookup(ctx, s.target.varName)} := ${mp}`);
          break;
        }
        // Bind the RHS before resolving a mapping key (or any keyed/indexed target below) so a
        // side-effecting key (m[inc()] = inc()) does not run before a side-effecting RHS - solc
        // evaluates the RHS first. The optimizer collapses the temp for pure operands (byte-identical).
        const valExpr = this.lowerExpr(s.value, ctx, out);
        const value = this.fresh();
        out.push(`let ${value} := ${valExpr}`);
        if (s.target.kind === 'local') {
          out.push(`${this.ctxLookup(ctx, s.target.varName)} := ${value}`);
        } else if (s.target.kind === 'immutableStaged') {
          // this.<imm> = v in the constructor: write the staged shadow (baked via setimmutable).
          out.push(`${ctx.immStaged!.get(s.target.name)!} := ${value}`);
          // Mirror into the reserved creation-block memory cell (if any ctor-reachable helper reads this
          // immutable) so the helper's mload sees the staged value at the point it is called (solc reads
          // the staged value during construction, last-write-wins).
          if (ctx.ctorImmShadow && ctx.ctorImmShadow.has(s.target.name))
            out.push(`mstore(${ctx.ctorImmShadow.get(s.target.name)!}, ${value})`);
        } else if (s.target.kind === 'mapping') {
          const slot = this.mappingSlot(s.target.baseSlot, s.target.keys, ctx, out);
          for (const l of this.storeState(s.target.type, slot, 0, value)) out.push(l);
        } else if (s.target.kind === 'aggFieldStore' || s.target.kind === 'memDynNestedFieldStore') {
          // xs[i].a = v / v.t.n = v: a VALUE leaf of a memory aggregate (RHS already bound above). (A value
          // leaf normally breaks in an earlier special-case block; this is the type-safe fall-through.)
          this.lowerAssignValue(s.target, value, ctx, out);
        } else {
          for (const l of this.storeState(s.target.type, String(s.target.slot), s.target.offset, value)) out.push(l);
        }
        break;
      }
      case 'exprStmt': {
        // a bytes-reference expression as a statement (a bare `addr.call({...});` discarding the
        // returndata) is lowered via lowerDynamic: the call + success checks still run, the value
        // is dropped. lowerExpr would throw (a reference value in a non-reference context).
        if (s.expr.kind === 'extCall') {
          this.lowerDynamic(s.expr, ctx, out);
          break;
        }
        // a value-returning high-level interface call whose result is DISCARDED (`IFoo(a).f();`): solc still
        // VALIDATES the returndata (size + ABI decode) even when unused, so run the decode for its side
        // effect (a short/malformed return reverts identically) and drop the decoded value.
        if (s.expr.kind === 'abiDecode') {
          this.lowerAbiDecode(s.expr.data, s.expr.types ?? (s.expr.type ? [s.expr.type] : []), ctx, out);
          break;
        }
        // Phase 2a: proxyInit/upgradeProxy are void EIP-1967 statements (sstore + emit + optional
        // delegatecall); they emit Yul statements directly, with no value to pop.
        if (s.expr.kind === 'proxyInit' || s.expr.kind === 'upgradeProxy') {
          this.lowerProxyMutate(s.expr, ctx, out);
          break;
        }
        // Phase 2d: proxyInitBeacon is a void EIP-1967 BEACON-slot statement (sstore beacon + emit
        // BeaconUpgraded + optional beacon-routed delegatecall); emits Yul directly, no value to pop.
        if (s.expr.kind === 'proxyInitBeacon') {
          this.lowerProxyInitBeacon(s.expr, ctx, out);
          break;
        }
        // Phase 3 DIAMOND: diamondInit (owner wiring + ERC-165 ids + event) and __diamondDelegateInit
        // (the _init delegatecall) are void statements emitting Yul directly, no value to pop.
        if (s.expr.kind === 'diamondInit') {
          this.lowerDiamondInit(s.expr, ctx, out);
          break;
        }
        if (s.expr.kind === 'diamondDelegateInit') {
          this.lowerDiamondDelegateInit(s.expr, ctx, out);
          break;
        }
        // Phase 3 DIAMOND (packed): __diamondCutPacked() is the whole diamond-2 add/replace/remove loop,
        // a void statement reading _diamondCut from calldata and SSTOREing the packed storage.
        if (s.expr.kind === 'diamondCutPacked') {
          this.lowerDiamondCutPacked(out);
          break;
        }
        // Phase 3 DIAMOND (solidstate): the solidstate ctor primitive, the cut (custom-error variant), and
        // the bare-selector custom-error revert - all void statements emitting Yul directly.
        if (s.expr.kind === 'diamondInitSolidstate') {
          this.lowerDiamondInitSolidstate(s.expr, ctx, out);
          break;
        }
        if (s.expr.kind === 'diamondCutSolidstate') {
          this.lowerDiamondCutSolidstate(out);
          break;
        }
        if (s.expr.kind === 'revertSelector') {
          out.push(`mstore(0x00, shl(224, ${'0x' + s.expr.selector.toString(16).padStart(8, '0')}))`);
          out.push('revert(0x00, 0x04)');
          break;
        }
        // A VOID-returning call through a function pointer as a statement: the dispatcher returns no
        // value, so emit the call bare (a `pop(...)` on a 0-value call is a Yul type error).
        if (s.expr.kind === 'funcRefCall' && s.expr.sig.kind === 'funcref' && s.expr.sig.ret === undefined) {
          const sig = s.expr.sig as JethType & { kind: 'funcref' };
          this.ensureFuncRefDispatcher(sig);
          const idReg = this.lowerExpr(s.expr.ptr, ctx, out);
          const idTmp = this.fresh();
          out.push(`let ${idTmp} := ${idReg}`);
          const args = this.lowerCallArgs(s.expr.args, ctx, out);
          out.push(`${this.funcRefDispatcherName(sig)}(${[idTmp, ...args].join(', ')})`);
          break;
        }
        const v = this.lowerExpr(s.expr, ctx, out);
        out.push(`pop(${v})`);
        break;
      }
      case 'callStmt': {
        // an internal call as a statement: the result (if any) is discarded.
        const args = this.lowerCallArgs(s.args, ctx, out);
        const call = `${this.userFnName(s.fn)}(${args.join(', ')})`;
        const isVoid = this.funcs.get(s.fn)?.returnType.kind === 'void';
        out.push(isVoid ? call : `pop(${call})`);
        break;
      }
      case 'deleteStmt': {
        this.lowerDelete(s.target, ctx, out);
        break;
      }
      case 'tupleDecl': {
        // `let [a, , c] = src`: bind a fresh local per non-skipped component.
        const temps = this.lowerDestructureSource(s.source, ctx, out);
        s.names.forEach((nm, i) => {
          if (nm === null) return;
          const ln = this.freshLocal(nm);
          out.push(`let ${ln} := ${temps[i]}`);
          this.ctxDeclare(ctx, nm, ln);
        });
        break;
      }
      case 'tupleAssign': {
        // `[a, , c] = src`: RHS fully evaluated into temps, then store into each non-skipped
        // target by reusing the assign lowering (feed the temp as a rawReg value).
        const temps = this.lowerDestructureSource(s.source, ctx, out);
        s.targets.forEach((tgt, i) => {
          if (tgt === null) return;
          for (const l of this.lowerStmt(
            { kind: 'assign', target: tgt, value: { kind: 'rawReg', type: tgt.type, reg: temps[i]! } },
            ctx,
          ))
            out.push(l);
        });
        break;
      }
      case 'block': {
        out.push('{');
        for (const l of this.lowerBlock(s.body, ctx)) out.push('  ' + l);
        out.push('}');
        break;
      }
      case 'modifierBody': {
        // Phase 5 (full modifiers): a `_;` placeholder inside a dispatch-lowered modifierWrap. Call the
        // synthesized body function userfn_<key>(<args>); a `return` inside it sets the userfn's ret
        // var(s) and leaves (running no more body code) but returns control here so the ENCLOSING
        // post-code still runs. Capture the result(s) into the buffered retVars (void -> a bare call;
        // multi-value -> `r0, r1 := userfn(...)`). With N placeholders this marker recurs N times, so
        // the body runs N times and retVars hold the LAST run's value(s) - byte-identical to solc.
        const md = ctx.modifierDispatch;
        if (!md) throw new UnsupportedError('modifierBody marker lowered outside a modifier dispatch');
        const call = `${md.userFn}(${md.args.join(', ')})`;
        out.push(md.retVars.length === 0 ? call : `${md.retVars.join(', ')} := ${call}`);
        break;
      }
      case 'ctorOutlineBind': {
        // W5D-1: outline a return-involving ctor unit (the level's own body, or a whole base-level
        // modifier wrap) into a creation-block Yul function, so a bare `return;` inside it lowers to
        // `leave` and exits ONLY that unit (byte-identical to solc's per-constructor / per-modifier-
        // layer return scoping). The bind sits where the level's params are un-shadowed: resolve each
        // param's CURRENT register for the call sites (a later modifier argDecl of the same name
        // shadows the ctx entry, so resolution must happen here). Params ride as single Yul words
        // (a value, or a memory-image pointer for an aggregate) - the exact representation the
        // enclosing jeth_constructor uses. Staged immutables thread in/out (pass-through when the
        // unit never writes them), preserving last-write-wins across multiple placeholder runs.
        if (!ctx.fnMode || ctx.specialEntry || ctx.modifierDispatch)
          throw new UnsupportedError('ctorOutlineBind lowered outside a constructor body');
        const argRegs = s.params.map((p) => this.ctxLookup(ctx, p.name));
        const fnName = `jeth_ctor_ol_${s.id}`;
        const sub: LowerCtx = {
          scopes: [new Map()],
          returnType: { kind: 'void' } as JethType,
          dynParams: new Map(),
          cdArrays: new Map(),
          cdAggregates: new Map(),
          cdDynStructs: new Map(),
          cdParamHead: new Map(),
          fnMode: { retVar: null }, // a bare `return;` in the unit -> leave (exit the unit only)
        };
        if (ctx.ctorImmShadow) sub.ctorImmShadow = ctx.ctorImmShadow;
        const formals: string[] = [];
        for (const p of s.params) {
          const f = this.freshLocal(p.name);
          this.ctxDeclare(sub, p.name, f);
          formals.push(f);
        }
        const immNames = [...(ctx.immStaged?.keys() ?? [])];
        const immIns: string[] = [];
        const immOuts: string[] = [];
        const subStaged = new Map<string, string>();
        for (const nm of immNames) {
          const iin = this.fresh();
          const iout = this.fresh();
          immIns.push(iin);
          immOuts.push(iout);
          subStaged.set(nm, iout);
        }
        if (immNames.length) sub.immStaged = subStaged;
        const unitLines: string[] = [];
        immNames.forEach((nm, k) => unitLines.push(`${immOuts[k]} := ${immIns[k]}`));
        for (const st of s.body) for (const l of this.lowerStmt(st, sub)) unitLines.push(l);
        const sig = `function ${fnName}(${[...formals, ...immIns].join(', ')})${immOuts.length ? ` -> ${immOuts.join(', ')}` : ''}`;
        this.ctorOutlineDefs.push(`${sig} {\n${unitLines.map((l) => '  ' + l).join('\n')}${unitLines.length ? '\n' : ''}}`);
        this.ctorOutlines.set(s.id, { fnName, argRegs, immNames });
        break; // the bind emits no inline code (the defs are hoisted next to jeth_constructor)
      }
      case 'ctorOutlineCall': {
        const rec = this.ctorOutlines.get(s.id);
        if (!rec) throw new UnsupportedError('ctorOutlineCall lowered before its ctorOutlineBind');
        const immVars = rec.immNames.map((nm) => ctx.immStaged!.get(nm)!);
        const call = `${rec.fnName}(${[...rec.argRegs, ...immVars].join(', ')})`;
        out.push(immVars.length ? `${immVars.join(', ')} := ${call}` : call);
        break;
      }
      case 'if': {
        const c = this.lowerExpr(s.cond, ctx, out); // short-circuit prep lands in `out`
        if (!s.else) {
          out.push(`if ${c} {`);
          for (const l of this.lowerBlock(s.then, ctx)) out.push('  ' + l);
          out.push('}');
        } else {
          // if-else: Yul `if` has no else, so switch on the bool (verified vs solc).
          out.push(`switch ${c}`);
          out.push('case 0 {');
          for (const l of this.lowerBlock(s.else, ctx)) out.push('  ' + l);
          out.push('}');
          out.push('default {');
          for (const l of this.lowerBlock(s.then, ctx)) out.push('  ' + l);
          out.push('}');
        }
        break;
      }
      case 'while': {
        // for {} 1 {} { if iszero(cond) { break } body } -- cond re-checked each
        // iteration (its prep statements must run inside the loop), continue OK.
        out.push('for {} 1 {} {');
        const inner: string[] = [];
        const c = this.lowerExpr(s.cond, ctx, inner);
        inner.push(`if iszero(${c}) { break }`);
        for (const l of this.lowerBlock(s.body, ctx)) inner.push(l);
        for (const l of inner) out.push('  ' + l);
        out.push('}');
        break;
      }
      case 'doWhile': {
        // do { body } while(cond). Compiled as `for {} run { run := cond } { body }`:
        // the body runs first (run starts 1), then the post re-evaluates cond into run,
        // then the for-condition re-checks. A `continue` in body jumps to the post (so it
        // re-evaluates cond, exactly like Solidity/C), and `break` exits immediately.
        const run = this.fresh();
        out.push(`let ${run} := 1`);
        const post: string[] = [];
        const c = this.lowerExpr(s.cond, ctx, post);
        post.push(`${run} := ${c}`);
        out.push(`for {} ${run} {`);
        for (const l of post) out.push('  ' + l);
        out.push('} {');
        for (const l of this.lowerBlock(s.body, ctx)) out.push('  ' + l);
        out.push('}');
        break;
      }
      case 'for': {
        this.ctxPush(ctx); // for-init scope encloses cond/post/body
        const initLines = s.init ? this.lowerStmt(s.init, ctx) : [];
        const postLines = s.post ? this.lowerStmt(s.post, ctx) : [];
        const bodyLines: string[] = [];
        if (s.cond) {
          const c = this.lowerExpr(s.cond, ctx, bodyLines);
          bodyLines.push(`if iszero(${c}) { break }`);
        }
        for (const l of this.lowerBlock(s.body, ctx)) bodyLines.push(l);
        out.push('for {');
        for (const l of initLines) out.push('  ' + l);
        out.push('} 1 {');
        for (const l of postLines) out.push('  ' + l);
        out.push('} {');
        for (const l of bodyLines) out.push('  ' + l);
        out.push('}');
        this.ctxPop(ctx);
        break;
      }
      case 'break':
        out.push('break');
        break;
      case 'continue':
        out.push('continue');
        break;
      case 'require': {
        // solc order: fully evaluate the condition first (so a side-effecting
        // condition reverts before the reason), THEN evaluate the reason's args
        // eagerly (a custom-error arg like 10/b reverts even when cond is true).
        const condExpr = this.lowerExpr(s.cond, ctx, out);
        const condTmp = this.fresh();
        out.push(`let ${condTmp} := ${condExpr}`);
        const reasonLines = this.lowerRevertReason(s.reason, ctx, out);
        out.push(`if iszero(${condTmp}) {`);
        for (const l of reasonLines) out.push('  ' + l);
        out.push('}');
        break;
      }
      case 'revert': {
        for (const l of this.lowerRevertReason(s.reason, ctx, out)) out.push(l);
        break;
      }
      case 'revertWith': {
        // bubble raw bytes as the revert payload: revert(add(b,0x20), mload(b)).
        const { mp } = this.toMemory(this.lowerDynamic(s.value, ctx, out), out);
        out.push(`revert(add(${mp}, 0x20), mload(${mp}))`);
        break;
      }
      case 'emit': {
        for (const l of this.lowerEmit(s.event, s.args, ctx, out)) out.push(l);
        break;
      }
      case 'push': {
        if (s.arr.elem.kind === 'struct') {
          this.lowerStructPush(s.arr, s.value, ctx, out);
        } else if (s.arr.elem.kind === 'bytes' || s.arr.elem.kind === 'string') {
          this.lowerStrPush(s.arr, s.value, ctx, out);
        } else if (s.arr.elem.kind === 'array') {
          // push a whole inner array onto a nested array (this.dd.push(xs) / push([])):
          // grow the outer, then deep-copy the value into the freshly grown inner slot.
          this.lowerArrayPush(s.arr, s.value, ctx, out);
        } else {
          // W7B: the value expression is lowered INSIDE lowerPush, after the base ref (solc's
          // left-to-right order) and frozen before the grow (arg-first).
          this.lowerPush(s.arr, s.value, ctx, out);
        }
        break;
      }
      case 'pop':
        if (s.arr.elem.kind === 'struct') this.lowerStructPop(s.arr, ctx, out);
        else if (s.arr.elem.kind === 'bytes' || s.arr.elem.kind === 'string') this.lowerStrPop(s.arr, ctx, out);
        else this.lowerPop(s.arr, ctx, out);
        break;
      case 'bytesPush': {
        const slot = this.bytesLocSlot(s.loc, ctx, out);
        const v = s.value ? this.lowerExpr(s.value, ctx, out) : '0';
        out.push(`${this.strPush()}(${slot}, ${v})`);
        break;
      }
      case 'bytesPop': {
        const slot = this.bytesLocSlot(s.loc, ctx, out);
        out.push(`${this.strPop()}(${slot})`);
        break;
      }
      case 'tryCatch': {
        this.lowerTryCatch(s, ctx, out);
        break;
      }
    }
    return out;
  }

  /** Feature 2: lower a try/catch around a high-level interface call. Mirrors solc:
   *    ok, ret := <CALL/STATICCALL, returndata captured, NO auto-bubble>
   *    switch ok
   *    case 0 { <catch: bind e=ret + this.reason/this.panic; run catch body> }
   *    default {
   *      if iszero(extcodesize(addr)) { revert(0, 0) }   // a non-contract -> OUTER revert empty
   *      <decode ret into the bound success vars (short returndata -> OUTER revert empty)>
   *      <run try body>
   *    } */
  private lowerTryCatch(s: Stmt & { kind: 'tryCatch' }, ctx: LowerCtx, out: string[]): void {
    // the controlling call WITHOUT bubble/codeGuard (the analyzer cleared both): we get ok + the
    // captured returndata blob + the addr register (for the in-ok-branch extcodesize guard).
    const { okReg, dataPtr, addrReg } = this.emitExtCall(s.call, ctx, out);
    out.push(`switch ${okReg}`);

    // ---- failure (ok==0): the catch body ----
    out.push('case 0 {');
    const catchOut: string[] = [];
    this.ctxPush(ctx);
    // `this.reason` / `this.panic` are soft-decoded from the verbatim returndata blob bound here.
    this.ctxDeclare(ctx, EXT_CALL_DATA_BINDING, dataPtr);
    if (s.catchName !== null) {
      // `e: bytes` is a memory bytes local; its register IS the [len][data] pointer (the captured blob).
      const ev = this.freshLocal(s.catchName);
      catchOut.push(`let ${ev} := ${dataPtr}`);
      this.ctxDeclare(ctx, s.catchName, ev);
    }
    for (const l of this.lowerBlock(s.catchBody, ctx)) catchOut.push(l);
    this.ctxPop(ctx);
    for (const l of catchOut) out.push('  ' + l);
    out.push('}');

    // ---- success (ok==1): codeGuard, decode the return, run the try body ----
    out.push('default {');
    const okOut: string[] = [];
    okOut.push(`if iszero(extcodesize(${addrReg})) { revert(0, 0) }`);
    this.ctxPush(ctx);
    if (s.retTypes.length > 0) {
      // decode the captured returndata blob into one register per bound component (short/empty
      // returndata reverts EMPTY as an OUTER revert, via lowerAbiDecode's blob bounds). The data
      // source is the EXT_CALL_DATA_BINDING (the blob pointer), reusing the addr.call decode path.
      this.ctxDeclare(ctx, EXT_CALL_DATA_BINDING, dataPtr);
      const dataExpr: Expr = { kind: 'callData', type: { kind: 'bytes' } };
      const temps = this.lowerAbiDecode(dataExpr, s.retTypes, ctx, okOut);
      s.retNames.forEach((nm, i) => {
        if (nm === null) return;
        const ln = this.freshLocal(nm);
        okOut.push(`let ${ln} := ${temps[i]}`);
        this.ctxDeclare(ctx, nm, ln);
      });
    }
    for (const l of this.lowerBlock(s.tryBody, ctx)) okOut.push(l);
    this.ctxPop(ctx);
    for (const l of okOut) out.push('  ' + l);
    out.push('}');
  }

  /** Feature 2: SOFT-decode `this.reason` (the Error(string) message) from the catch returndata blob.
   *  Returns a memory [len][data] pointer: the decoded string when the blob is a well-formed
   *  Error(string), else an EMPTY string (it MUST NOT hard-revert on a malformed payload - solc yields
   *  "" there). Byte-identical to solc's `catch Error(string memory reason)` extraction: pre-validate
   *  EXACTLY the bounds abiDecFromMem (the abi.decode string codec) would check for a string at e[4:]
   *  decoded as (string); if all pass, the hard decode cannot revert, so reuse abiDecFromMem. */
  private lowerCatchReason(ctx: LowerCtx, out: string[]): string {
    const blob = this.ctxLookup(ctx, EXT_CALL_DATA_BINDING); // [len][e bytes]
    // default result: a fresh EMPTY string image (length 0 = one zeroed word).
    const rptr = this.fresh();
    out.push(`let ${rptr} := ${this.alloc()}(0x20)`);
    out.push(`mstore(${rptr}, 0)`);
    // e-bytes region: blobData = add(blob, 0x20) (start of e), eEnd = add(blobData, len_e).
    const blobData = this.fresh();
    out.push(`let ${blobData} := add(${blob}, 0x20)`);
    const eEnd = this.fresh();
    out.push(`let ${eEnd} := add(${blobData}, mload(${blob}))`);
    // Treat e[4:] as the abi.decode blob of `(string)`. innerData = e[4:] start = blobData + 4.
    // Condition 1: len_e >= 4 (selector) AND the outer 1-word head fits: innerData + 32 <= eEnd
    //   (lowerAbiDecode's `gt(add(blobData, 32), blobEnd)` over the inner blob; here innerData = blobData+4).
    // Condition 2: the selector == 0x08c379a0.
    out.push(`if and(iszero(lt(mload(${blob}), 36)), eq(shr(224, mload(${blobData})), 0x08c379a0)) {`);
    const inner: string[] = [];
    const innerData = this.fresh();
    inner.push(`let ${innerData} := add(${blobData}, 4)`); // e[4:] = the (string) tuple blob
    // offset word (relative to innerData), bounded like lowerAbiDecode's dynamic component.
    const so = this.fresh();
    inner.push(`let ${so} := mload(${innerData})`);
    const se = this.fresh();
    inner.push(`let ${se} := add(${innerData}, ${so})`);
    // length word in-blob: `se + 32 <= eEnd` (cdElemHeadBytes(string) = 32). offset cap: so <= 2^64-1.
    inner.push(`if and(iszero(gt(${so}, 0xffffffffffffffff)), iszero(gt(add(${se}, 32), ${eEnd}))) {`);
    const lvl2: string[] = [];
    const slen = this.fresh();
    lvl2.push(`let ${slen} := mload(${se})`); // the string byte length
    // abiDecFromMem(string) bounds: len <= 2^64-1 (Panic 0x41) AND data fits: se + 0x20 + len <= eEnd.
    lvl2.push(`if and(iszero(gt(${slen}, 0xffffffffffffffff)), iszero(gt(add(add(${se}, 0x20), ${slen}), ${eEnd}))) {`);
    const ok: string[] = [];
    // all bounds pass -> the hard string decode is guaranteed not to revert; reuse abiDecFromMem.
    const dst = this.fresh();
    ok.push(`let ${dst} := mload(0x40)`);
    const sz = this.abiDecFromMem({ kind: 'string' }, se, dst, eEnd, ok);
    ok.push(`mstore(0x40, add(${dst}, ${sz}))`);
    ok.push(`${rptr} := ${dst}`);
    for (const l of ok) lvl2.push('  ' + l);
    lvl2.push('}');
    for (const l of lvl2) inner.push('  ' + l);
    inner.push('}');
    for (const l of inner) out.push('  ' + l);
    out.push('}');
    return rptr;
  }

  /** Lower a Stmt[] branch in a fresh ctx scope (mirrors a Yul block scope). */
  private lowerBlock(body: Stmt[], ctx: LowerCtx): string[] {
    this.ctxPush(ctx);
    const inner: string[] = [];
    for (const s of body) for (const l of this.lowerStmt(s, ctx)) inner.push(l);
    this.ctxPop(ctx);
    return inner;
  }

  // ---- reverts / custom errors --------------------------------------------

  /** Lower a revert payload. MAY append eager prep (custom-error arg temps) to
   *  `out`; returns the lines that perform the actual revert (placed at the
   *  revert point: inline for `revert`, inside the guard for `require`). */
  private lowerRevertReason(r: RevertReason, ctx: LowerCtx, out: string[]): string[] {
    // W6A: the revert payload is ABI-encoded and thrown immediately - a TRANSIENT capture context.
    return this.inTransientCapture(() => this.lowerRevertReasonInner(r, ctx, out));
  }

  private lowerRevertReasonInner(r: RevertReason, ctx: LowerCtx, out: string[]): string[] {
    switch (r.kind) {
      case 'empty':
        return ['revert(0, 0)'];
      case 'panic':
        return [`${this.panic()}(0x${r.code.toString(16).padStart(2, '0')})`];
      case 'errorString':
        return this.lowerErrorString(r.message);
      case 'errorStringDyn': {
        // Error(string) from a runtime value. solc evaluates the message EXPRESSION eagerly - its
        // side effects run even when a require condition holds (require(cond, ev()) runs ev() either
        // way) - so materialize the message into memory NOW (into `out`, before any cond guard),
        // mirroring the 'custom' path's eager-arg evaluation. Only the Error(string) blob build +
        // revert are deferred into the returned (guarded) lines. Deferring the eval was a silent
        // MISCOMPILE: the message's state writes were dropped on the require-passes path.
        const ref = this.lowerDynamic(r.value, ctx, out);
        const { mp, len } = this.toMemory(ref, out);
        const lenTmp = this.fresh();
        out.push(`let ${lenTmp} := ${len}`);
        const lines: string[] = [];
        const padded = `and(add(${lenTmp}, 0x1f), not(0x1f))`;
        // Build the Error(string) blob at the FREE POINTER (past the materialized source), NOT at the
        // memory-0 scratch: when the source string was freshly allocated (a string literal, a ternary
        // selecting a literal), the scratch blob's data region [0x44, 0x44+padded) overlaps that buffer,
        // and the Yul backend mis-lowers the overlapping mcopy across a switch (empty revert for len>=61).
        const p = this.fresh();
        lines.push(`let ${p} := mload(0x40)`);
        lines.push(`mstore(${p}, shl(224, 0x08c379a0))`);
        lines.push(`mstore(add(${p}, 4), 0x20)`);
        lines.push(`mstore(add(${p}, 0x24), ${lenTmp})`);
        lines.push(`mcopy(add(${p}, 0x44), add(${mp}, 0x20), ${padded})`);
        lines.push(`revert(${p}, add(0x44, ${padded}))`);
        return lines;
      }
      case 'custom': {
        // Evaluate args eagerly into temps so they run before any cond guard
        // (matches solc: a custom-error arg can revert even when require passes).
        // Fast path: every arg is a static VALUE (one word each, no struct/array/dynamic).
        if (!r.args.some((a) => isDynamicType(a.type) || a.type.kind === 'struct' || a.type.kind === 'array')) {
          const argTemps = r.args.map((a) => {
            const v = this.lowerExpr(a, ctx, out);
            const t = this.fresh();
            out.push(`let ${t} := ${v}`);
            return t;
          });
          const helper = this.errorRevert(argTemps.length);
          return [`${helper}(0x${r.decl.selector}${argTemps.map((a) => ', ' + a).join('')})`];
        }
        // head/tail: a static value is one head word; a static struct / fixed-array occupies its
        // abiHeadWords leaf words INLINE in the head; a dynamic bytes/string/array writes a head
        // offset word + a tail blob. Tail offsets are relative to the args region (calldata byte 4).
        // W7A TWO-PHASE: every argument evaluates LEFT-TO-RIGHT to a value/handle first
        // (prepEncodeComponent - the same phase-1 taxonomy abi.encode and event data use), then the
        // payload serializes through the handles LATE (sibling mutations visible, storage read
        // post-sibling, validation Panics at serialize time - probes A4/P6).
        const headWordsOf = (t: JethType): number => (isDynamicType(t) ? 1 : abiHeadWords(t));
        const lines: string[] = [];
        type LA =
          | { dyn: 'static'; word: string }
          | { dyn: 'agg'; mp: string; words: number }
          | { dyn: 'bytes'; mp: string; len: string }
          | { dyn: 'array'; mp: string; size: string };
        const prevPatches = this.beginTwoPhase();
        const preps = r.args.map((a) => this.prepEncodeComponent(a, ctx, lines));
        this.flushTwoPhase(prevPatches, lines);
        const lowered: LA[] = preps.map((finish): LA => {
          const part = finish(lines);
          if ('word' in part) return { dyn: 'static', word: part.word };
          if ('inline' in part) return { dyn: 'agg', mp: part.mp, words: part.words };
          if ('len' in part) return { dyn: 'bytes', mp: part.mp, len: part.len };
          return { dyn: 'array', mp: part.mp, size: part.size };
        });
        const headSize = r.args.reduce((n, a) => n + headWordsOf(a.type), 0) * 32;
        const p = this.fresh();
        lines.push(`let ${p} := mload(0x40)`);
        lines.push(`mstore(${p}, shl(224, 0x${r.decl.selector}))`);
        const cur = this.fresh();
        lines.push(`let ${cur} := ${headSize}`); // byte offset (rel byte 4) of next tail
        let hw = 0; // running head-word index
        lowered.forEach((a) => {
          const headAt = `add(${p}, ${4 + hw * 32})`;
          if (a.dyn === 'static') {
            lines.push(`mstore(${headAt}, ${a.word})`);
            hw += 1;
          } else if (a.dyn === 'agg') {
            // static aggregate: its abiHeadWords leaf words inline (no offset, no tail).
            lines.push(`mcopy(${headAt}, ${a.mp}, ${a.words * 32})`);
            hw += a.words;
          } else if (a.dyn === 'bytes') {
            lines.push(`mstore(${headAt}, ${cur})`);
            const padded = this.fresh();
            lines.push(`let ${padded} := and(add(${a.len}, 0x1f), not(0x1f))`);
            lines.push(`mstore(add(${p}, add(4, ${cur})), ${a.len})`);
            lines.push(`mcopy(add(${p}, add(4, add(${cur}, 0x20))), add(${a.mp}, 0x20), ${padded})`);
            lines.push(`${cur} := add(${cur}, add(0x20, ${padded}))`);
            hw += 1;
          } else {
            // array tail blob [len][elements...] is already ABI-encoded: copy it verbatim.
            lines.push(`mstore(${headAt}, ${cur})`);
            lines.push(`mcopy(add(${p}, add(4, ${cur})), ${a.mp}, ${a.size})`);
            lines.push(`${cur} := add(${cur}, ${a.size})`);
            hw += 1;
          }
        });
        lines.push(`revert(${p}, add(4, ${cur}))`);
        return lines;
      }
    }
  }

  /** Byte-exact Error(string) revert blob (verified against solc): selector
   *  0x08c379a0, ABI offset 0x20, length, then ceil(len/32) right-padded words. */
  private lowerErrorString(message: Uint8Array): string[] {
    const len = message.length;
    const lines: string[] = [];
    lines.push('mstore(0, shl(224, 0x08c379a0))'); // selector in high 4 bytes
    lines.push('mstore(4, 0x20)'); // ABI offset to the string data
    lines.push(`mstore(0x24, ${len})`); // string length
    const nWords = Math.ceil(len / 32); // 0 words when len === 0
    for (let i = 0; i < nWords; i++) {
      lines.push(`mstore(${0x44 + i * 32}, ${wordFromBytes(message, i * 32)})`);
    }
    lines.push(`revert(0, ${4 + 32 + 32 + nWords * 32})`);
    return lines;
  }

  /** A stable Yul name for the per-signature function-pointer dispatcher. Derived from the funcref
   *  signature's canonical name so every call through the same pointer type shares one dispatcher. */
  private funcRefDispatcherName(sig: JethType & { kind: 'funcref' }): string {
    const key = `${sig.params.map(canonicalName).join(',')}->${sig.ret ? canonicalName(sig.ret) : 'void'}`;
    return `funcref_dispatch_${toHex(keccak(key)).slice(0, 16)}`;
  }

  /** Emit (once, into the helpers map) the dispatcher for a function-pointer signature: a Yul function
   *  `f(id, args...) -> ret` that switches on the stable dispatch id and calls the matching userfn_. The
   *  default arm (id 0 = the null pointer, or any unknown id) REVERTS with empty data - exactly solc's
   *  behavior on calling a zero-initialized/invalid internal function pointer. Every address-taken
   *  function whose signature equals `sig` becomes a case; the analyzer guaranteed each is emitted. */
  private ensureFuncRefDispatcher(sig: JethType & { kind: 'funcref' }): void {
    const name = this.funcRefDispatcherName(sig);
    if (this.helpers.has(name)) return;
    const argNames = sig.params.map((_, i) => `a${i}`);
    const retDecl = sig.ret ? ' -> ret' : '';
    const cases: string[] = [];
    // Collect the matching targets (by exact signature) with their ids, ordered by id for stable output.
    const targets: { id: number; key: string }[] = [];
    for (const [key, id] of this.contract?.funcRefIds ?? []) {
      const fn = this.funcs.get(key);
      if (!fn || fn.returnTypes) continue;
      const fsig: JethType = {
        kind: 'funcref',
        params: fn.params.map((p) => p.type),
        ret: fn.returnType.kind === 'void' ? undefined : fn.returnType,
      };
      if (typesEqual(fsig, sig)) targets.push({ id, key });
    }
    targets.sort((x, y) => x.id - y.id);
    for (const t of targets) {
      const callExpr = `${this.userFnName(t.key)}(${argNames.join(', ')})`;
      cases.push(`  case ${t.id} { ${sig.ret ? `ret := ${callExpr}` : callExpr} }`);
    }
    // The default arm handles the NULL / unassigned pointer (id 0) and any unknown id: solc reverts a
    // call through a zero-initialized internal function pointer with Panic(0x51), so emit that exact
    // Panic (byte-identical returndata) rather than an empty revert.
    const panicFn = this.panic();
    const body = [
      `function ${name}(id${argNames.length ? ', ' + argNames.join(', ') : ''})${retDecl} {`,
      '  switch id',
      ...cases,
      `  default { ${panicFn}(0x51) }`,
      '}',
    ].join('\n');
    this.helpers.set(name, body);
  }

  /** Deduplicated custom-error revert helper for a given static-arg arity.
   *  Selector passed as the raw 4-byte value; shl(224,...) applied inside. */
  private errorRevert(n: number): string {
    const name = `revert_error_${n}`;
    if (!this.helpers.has(name)) {
      const params = ['sel', ...Array.from({ length: n }, (_, i) => `a${i}`)];
      const stores = Array.from({ length: n }, (_, i) => `  mstore(${4 + 32 * i}, a${i})`).join('\n');
      const total = 4 + 32 * n;
      this.helpers.set(
        name,
        `function ${name}(${params.join(', ')}) {\n  mstore(0, shl(224, sel))\n${stores}${stores ? '\n' : ''}  revert(0, ${total})\n}`,
      );
    }
    return name;
  }

  // ---- events / logs -------------------------------------------------------

  private lowerEmit(ev: EventIR, args: Expr[], ctx: LowerCtx, out: string[]): string[] {
    // W6A: topics + data are materialized and logged immediately - a TRANSIENT capture context.
    return this.inTransientCapture(() => this.lowerEmitInner(ev, args, ctx, out));
  }

  private lowerEmitInner(ev: EventIR, args: Expr[], ctx: LowerCtx, out: string[]): string[] {
    // partition into indexed topics (static) and the non-indexed data tuple.
    type Part = EncPart;
    // solc evaluates an event's INDEXED args FIRST in REVERSE source order, then its NON-INDEXED args
    // in forward source order (verified vs solc 0.8.35). The OUTPUT layout stays source order (topics[]
    // and the data tuple both follow source order), so materialize each param into a source-INDEXED
    // slot while VISITING in solc's eval order. (Visiting strictly source-order was a MISCOMPILE: a
    // mixed indexed/non-indexed event with side-effecting args produced different topic/data bytes.)
    // W7A: a TOPIC hashes its payload EAGERLY at the arg's evaluation position (F3-verified vs solc),
    // but the DATA tuple is TWO-PHASE: each non-indexed arg evaluates to a value/handle at its
    // position (dataPrep, via prepEncodeComponent) and SERIALIZES after every arg has run - late
    // reads through memory handles and storage slots, exactly like abi.encode (probes A9/P5).
    const topicSlot: (string | null)[] = ev.params.map(() => null);
    const dataPrep: (((o: string[]) => EncPart) | null)[] = ev.params.map(() => null);
    const dataSlot: (Part | null)[] = ev.params.map(() => null);
    const materialize = (i: number): void => {
      const p = ev.params[i]!;
      const arg = args[i]!;
      if (p.indexed && isBytesLike(p.type)) {
        // an indexed bytes/string topic is keccak256 of the CONTENT bytes (G4), not the value.
        const { mp, len } = this.toMemory(this.lowerDynamic(arg, ctx, out), out);
        const topic = this.fresh();
        out.push(`let ${topic} := keccak256(add(${mp}, 0x20), ${len})`);
        topicSlot[i] = topic;
      } else if (p.indexed && p.type.kind === 'struct' && isDynamicType(p.type)) {
        // an indexed DYNAMIC struct topic is keccak256 over the recursively FLATTENED payload
        // (static leaves inline; bytes/string -> content padded to a word, no length; dyn value-
        // array -> element words, no length; nested struct -> members concatenated). This is NOT
        // abi.encode (no offsets, no length words). Verified byte-identical to solc.
        const { mp, size } = this.encodeTopicBlob(arg, ctx, out);
        const topic = this.fresh();
        out.push(`let ${topic} := keccak256(${mp}, ${size})`);
        topicSlot[i] = topic;
      } else if (
        p.indexed &&
        isStaticType(p.type) &&
        (p.type.kind === 'struct' || (p.type.kind === 'array' && p.type.length !== undefined))
      ) {
        // an indexed STATIC fixed-array / struct topic is keccak256(abi.encode(value)) = keccak over
        // the padded leaf words (no length word). Verified byte-identical to solc.
        const { mp, size } = this.materializeStaticAggToMem(arg, ctx, out);
        const topic = this.fresh();
        out.push(`let ${topic} := keccak256(${mp}, ${size})`);
        topicSlot[i] = topic;
      } else if (p.indexed && p.type.kind === 'array' && isDynLeafTopicArray(p.type)) {
        // an indexed DYNAMIC-LEAF array (string[], bytes[], u256[][], string[][], Arr<string,N>,
        // Arr<u256[],N>, ...): topic = keccak256 of the packed-padded preimage - each leaf laid out
        // with NO length words and NO offset tables (a value leaf as its word; a bytes/string leaf as
        // its content padded to a 32-byte boundary; nested arrays concatenated). Built from the
        // materializeArrayArg ABI tail. Verified byte-identical to solc.
        // A DYNAMIC-outer array (bytes[]/string[]/u256[][]) and a CALLDATA-sourced FIXED-outer array
        // ride materializeArrayArg's ABI tail. A MEMORY-sourced FIXED-outer array (a memAggregate local /
        // literal Arr<bytes,N>/Arr<string,N>/Arr<u256[],N>) is intentionally NOT an abi.encode arg
        // (Edge D), so materializeArrayArg would throw JETH900; build its N-word-offset-table ABI tail
        // directly from the memory image instead. Both feed encodeArrayTopicBlob, whose fixed-outer
        // branch (base = tail) walks exactly this offset table.
        const { mp } = this.isMemFixedDynLeafArg(arg)
          ? this.materializeFixedDynLeafTail(arg, ctx, out)
          : this.materializeArrayArg(arg, ctx, out);
        const blob = this.encodeArrayTopicBlob(p.type as JethType & { kind: 'array' }, mp, out);
        const topic = this.fresh();
        out.push(`let ${topic} := keccak256(${blob.mp}, ${blob.size})`);
        topicSlot[i] = topic;
      } else if (p.indexed && p.type.kind === 'array') {
        // an indexed DYNAMIC value-element array topic is keccak256 of the element words (the
        // ABI tail minus its length word), not the value. Verified byte-identical to solc.
        const { mp, size } = this.materializeArrayArg(arg, ctx, out);
        const topic = this.fresh();
        out.push(`let ${topic} := keccak256(add(${mp}, 0x20), sub(${size}, 0x20))`);
        topicSlot[i] = topic;
      } else if (p.indexed) {
        // a static-value indexed topic: bind to a temp so the value is captured at eval time.
        const t = this.fresh();
        out.push(`let ${t} := ${this.lowerExpr(arg, ctx, out)}`);
        topicSlot[i] = t;
      } else {
        // W7A: a non-indexed DATA component - phase 1 only (value spill / handle capture at the
        // arg's evaluation position); the serialization runs after every arg (prepEncodeComponent's
        // finisher mirrors the pre-two-phase data taxonomy: bytes toMemory, static aggregates
        // inline via flatten/aggToMemPtr/storage-late, dyn structs to a blob, arrays to an ABI
        // tail, values as spilled words - byte-identical codecs, late reads).
        dataPrep[i] = this.prepEncodeComponent(arg, ctx, out);
      }
    };
    const indexedRev: number[] = [];
    const plainFwd: number[] = [];
    ev.params.forEach((p, i) => (p.indexed ? indexedRev.push(i) : plainFwd.push(i)));
    indexedRev.reverse();
    const prevPatches = this.beginTwoPhase();
    for (const i of indexedRev) this.withoutCapturePatches(() => materialize(i)); // topics hash eagerly
    for (const i of plainFwd) materialize(i);
    this.flushTwoPhase(prevPatches, out);
    // ---- serialize phase: finish each DATA component in source order (late reads). ----
    ev.params.forEach((_, i) => {
      if (dataPrep[i]) dataSlot[i] = dataPrep[i]!(out);
    });
    // assemble topics + data in SOURCE order from the per-param slots.
    const idxVals: string[] = [];
    const data: Part[] = [];
    ev.params.forEach((p, i) => {
      if (p.indexed) idxVals.push(topicSlot[i]!);
      else data.push(dataSlot[i]!);
    });
    // anonymous events carry NO topic0 (the signature hash); only the indexed params are topics
    // (LOG0 when there are none). Non-anonymous events always lead with topic0.
    const topicArgs = ev.anonymous ? idxVals : [`0x${ev.topic0}`, ...idxVals];
    const n = topicArgs.length;
    const topics = topicArgs.length ? `, ${topicArgs.join(', ')}` : '';
    const lines: string[] = [];
    if (data.length === 0) {
      lines.push(`log${n}(0, 0${topics})`);
      return lines;
    }
    // head word count: a value -> 1 word; a STATIC struct/fixed-array -> abiHeadWords inline; a
    // dynamic (bytes/string/array) -> 1 word (an offset into the tail).
    const headWords = data.reduce((acc, d) => acc + ('inline' in d ? d.words : 1), 0);
    const headSize = 32 * headWords;
    if (data.every((d) => 'word' in d || 'inline' in d)) {
      // all-static data: head only (value words + inline static-aggregate blobs), no tail.
      const m = this.fresh();
      lines.push(`let ${m} := mload(0x40)`);
      let hw = 0;
      for (const d of data) {
        const head = hw === 0 ? m : `add(${m}, ${32 * hw})`;
        if ('word' in d) {
          lines.push(`mstore(${head}, ${d.word})`);
          hw += 1;
        } else {
          lines.push(`mcopy(${head}, ${(d as { mp: string }).mp}, ${(d as { words: number }).words * 32})`);
          hw += (d as { words: number }).words;
        }
      }
      lines.push(`log${n}(${m}, ${headSize}${topics})`);
      return lines;
    }
    // mixed/dynamic data: ABI head/tail. Total size computed at runtime.
    const total = this.fresh();
    lines.push(`let ${total} := ${headSize}`);
    for (const d of data) {
      if ('len' in d) lines.push(`${total} := add(${total}, add(0x20, and(add(${d.len}, 0x1f), not(0x1f))))`);
      else if ('size' in d) lines.push(`${total} := add(${total}, ${d.size})`);
    }
    const ptr = this.fresh();
    lines.push(`let ${ptr} := ${this.alloc()}(${total})`);
    const cursor = this.fresh();
    lines.push(`let ${cursor} := add(${ptr}, ${headSize})`);
    let hw = 0;
    for (const d of data) {
      const head = hw === 0 ? ptr : `add(${ptr}, ${32 * hw})`;
      if ('word' in d) {
        lines.push(`mstore(${head}, ${d.word})`);
        hw += 1;
      } else if ('inline' in d) {
        // a STATIC struct/fixed-array: leaf words inline in the head (no offset/tail).
        lines.push(`mcopy(${head}, ${d.mp}, ${d.words * 32})`);
        hw += d.words;
      } else if ('len' in d) {
        const pad = `and(add(${d.len}, 0x1f), not(0x1f))`;
        lines.push(`mstore(${head}, sub(${cursor}, ${ptr}))`);
        lines.push(`mstore(${cursor}, ${d.len})`);
        lines.push(`mcopy(add(${cursor}, 0x20), add(${d.mp}, 0x20), ${pad})`);
        lines.push(`${cursor} := add(${cursor}, add(0x20, ${pad}))`);
        hw += 1;
      } else {
        // array tail blob [len][elements...]: copy verbatim (already ABI-encoded).
        lines.push(`mstore(${head}, sub(${cursor}, ${ptr}))`);
        lines.push(`mcopy(${cursor}, ${d.mp}, ${d.size})`);
        lines.push(`${cursor} := add(${cursor}, ${d.size})`);
        hw += 1;
      }
    }
    lines.push(`log${n}(${ptr}, ${total}${topics})`);
    return lines;
  }

  /** Emit storage write, handling packed slots via read-modify-write. `slot` is a
   *  Yul expression (a constant for a fixed slot, or a temp for a mapping element).
   *  solc uses read-modify-write even for a narrow mapping value, so the packed
   *  path reproduces mapping value storage byte-for-byte (verified). */
  private storeState(t: JethType, slot: string, offset: number, value: string): string[] {
    const size = storageByteSize(t);
    if (size === 32 && offset === 0) {
      return [`sstore(${slot}, ${value})`];
    }
    // packed: clear the field's bytes, OR in the (masked, shifted) value.
    // bytesN is held left-aligned in registers but stored right-aligned within
    // its field (verified against solc), so right-align it first.
    const fieldData = t.kind === 'bytesN' ? `shr(${(32 - size) * 8}, ${value})` : value;
    const fieldMask = (1n << BigInt(size * 8)) - 1n;
    const shift = BigInt(offset * 8);
    const clearMask = ((1n << 256n) - 1n) ^ (fieldMask << shift);
    const t0 = this.fresh();
    const t1 = this.fresh();
    return [
      `let ${t0} := and(sload(${slot}), ${toWord(clearMask)})`,
      `let ${t1} := shl(${shift}, and(${fieldData}, ${toWord(fieldMask)}))`,
      `sstore(${slot}, or(${t0}, ${t1}))`,
    ];
  }

  // ---- expressions ---------------------------------------------------------
  //
  // lowerExpr returns the Yul expression for a value and may append preparatory
  // statements (temps, short-circuit control flow) to `out`. Side-effecting or
  // conditionally-evaluated subexpressions therefore lower correctly.

  private lowerExpr(e: Expr, ctx: LowerCtx, out: string[]): string {
    switch (e.kind) {
      case 'literalInt':
        return toWord(e.value);
      case 'rawReg':
        return e.reg; // a pre-computed Yul register (tuple destructuring feeds it into the assign lowering)
      case 'literalBool':
        return e.value ? '1' : '0';
      case 'localRead':
        return this.ctxLookup(ctx, e.name);
      case 'stateRead':
        return this.loadState(e.type, String(e.slot), e.offset);
      case 'immutableRead':
        // a runtime read of an @immutable: the value baked into the code by setimmutable.
        // EXCEPT inside a creation-block copy of a ctor-reachable helper: solc forbids loadimmutable +
        // setimmutable of the same immutable in one assembly subroutine, so read the STAGED value from
        // the reserved creation-block memory cell instead (set up by emitConstructor).
        if (ctx.ctorImmShadow && ctx.ctorImmShadow.has(e.name)) return `mload(${ctx.ctorImmShadow.get(e.name)!})`;
        return `loadimmutable("${e.name}")`;
      case 'immutableStagedRead':
        // a read inside the constructor body: the staged shadow (a jeth_constructor return var).
        return ctx.immStaged!.get(e.name)!;
      case 'unary':
        return this.lowerUnary(e, ctx, out);
      case 'binary':
        return this.lowerBinary(e, ctx, out);
      case 'ternary': {
        // an aggregate ternary (static struct / static fixed array): materialize the taken
        // branch to a memory image (allocAggFromStorage copy / allocAggToMem / memAggregate
        // alias), then select the image POINTER with a short-circuit switch.
        if (e.type.kind === 'struct' || (e.type.kind === 'array' && e.type.length !== undefined)) {
          // a DYNAMIC-field struct uses the pointer-headed image builder (buildDynStructLocal);
          // a static aggregate uses the flat ABI-image materializer (aggToMemPtr).
          const dynStruct = e.type.kind === 'struct' && isDynamicType(e.type);
          const matPtr = (br: Expr, o: string[]): string =>
            dynStruct
              ? this.buildDynStructLocal(e.type as JethType & { kind: 'struct' }, br, ctx, o)
              : this.aggToMemPtr(br, ctx, o);
          const cc = this.lowerExpr(e.cond, ctx, out);
          const p = this.fresh();
          out.push(`let ${p} := 0`);
          // W7A: branch code lands in switch-case BLOCKS - suspend capture-patch recording there
          // (a patch's locals would be block-scoped and unreachable from the top-level flush).
          const tO: string[] = [];
          const pT = this.withoutCapturePatches(() => matPtr(e.then, tO));
          const eO: string[] = [];
          const pE = this.withoutCapturePatches(() => matPtr(e.else, eO));
          out.push(`switch ${cc}`);
          out.push('case 0 {');
          for (const l of eO) out.push('  ' + l);
          out.push(`  ${p} := ${pE}`);
          out.push('}');
          out.push('default {');
          for (const l of tO) out.push('  ' + l);
          out.push(`  ${p} := ${pT}`);
          out.push('}');
          return p;
        }
        if (e.type.kind === 'array' && e.type.length === undefined) {
          // a DYNAMIC value-array ternary: materialize the TAKEN branch to a memory [len][elems]
          // pointer (aggArgToMemPtr: storage/calldata copy, memory alias) and select it. Short-circuit
          // (only the taken branch is materialized), matching solc.
          const cc = this.lowerExpr(e.cond, ctx, out);
          const p = this.fresh();
          out.push(`let ${p} := 0`);
          // W7A: suspend capture-patch recording inside the switch-case branch blocks.
          const tO: string[] = [];
          const pT = this.withoutCapturePatches(() => this.aggArgToMemPtr(e.then, ctx, tO));
          const eO: string[] = [];
          const pE = this.withoutCapturePatches(() => this.aggArgToMemPtr(e.else, ctx, eO));
          out.push(`switch ${cc}`);
          out.push('case 0 {');
          for (const l of eO) out.push('  ' + l);
          out.push(`  ${p} := ${pE}`);
          out.push('}');
          out.push('default {');
          for (const l of tO) out.push('  ' + l);
          out.push(`  ${p} := ${pT}`);
          out.push('}');
          return p;
        }
        // short-circuit: only the taken branch is evaluated (a branch may revert / have
        // checked-arithmetic side effects), exactly like Solidity's c ? a : b.
        const c = this.lowerExpr(e.cond, ctx, out);
        const res = this.fresh();
        out.push(`let ${res} := 0`);
        const thenOut: string[] = [];
        const tv = this.lowerExpr(e.then, ctx, thenOut);
        const elseOut: string[] = [];
        const ev = this.lowerExpr(e.else, ctx, elseOut);
        out.push(`switch ${c}`);
        out.push('case 0 {');
        for (const s of elseOut) out.push('  ' + s);
        out.push(`  ${res} := ${ev}`);
        out.push('}');
        out.push('default {');
        for (const s of thenOut) out.push('  ' + s);
        out.push(`  ${res} := ${tv}`);
        out.push('}');
        return res;
      }
      case 'incDec': {
        // x++ / ++x in value position: read old, compute new (checked unless unchecked),
        // store, yield old (postfix) or new (prefix).
        const old = this.fresh();
        out.push(`let ${old} := ${this.lowerExpr(e.readExpr, ctx, out)}`);
        const nv = this.fresh();
        const raw = e.isInc ? `add(${old}, 1)` : `sub(${old}, 1)`;
        out.push(
          `let ${nv} := ${e.unchecked ? this.wrapToType(e.type, raw) : `${this.checkedArith(e.isInc ? 'add' : 'sub', e.type)}(${old}, 1)`}`,
        );
        this.lowerAssignValue(e.target, nv, ctx, out);
        return e.prefix ? nv : old;
      }
      case 'assignExpr': {
        // (x = v)/(x += v) in value position: compute the (already-coerced) new value,
        // store it into the target, and yield it. Matches Solidity's assignment-expression
        // result (the assigned, LHS-typed value).
        const v = this.fresh();
        out.push(`let ${v} := ${this.lowerExpr(e.value, ctx, out)}`);
        this.lowerAssignValue(e.target, v, ctx, out);
        return v;
      }
      case 'call': {
        // internal/private function call yielding a value: evaluate args (left-to-right,
        // each frozen into a temp), then the Yul function call IS the value.
        const args = this.lowerCallArgs(e.args, ctx, out);
        return `${this.userFnName(e.fn)}(${args.join(', ')})`;
      }
      case 'funcRef': {
        // An internal function-pointer VALUE: the target function's stable dispatch id, a plain word.
        const id = this.contract?.funcRefIds?.get(e.fn);
        if (id === undefined) throw new UnsupportedError(`no dispatch id assigned for function pointer '${e.fn}'`);
        return String(id);
      }
      case 'funcRefCall': {
        // A CALL THROUGH a function pointer: evaluate the id, then the arguments (left-to-right, each
        // frozen into a temp, matching an ordinary internal call), then invoke the per-signature
        // dispatcher which switches on the id and calls the matching userfn_.
        const sig = e.sig as JethType & { kind: 'funcref' };
        this.ensureFuncRefDispatcher(sig);
        const idReg = this.lowerExpr(e.ptr, ctx, out);
        const idTmp = this.fresh();
        out.push(`let ${idTmp} := ${idReg}`);
        const args = this.lowerCallArgs(e.args, ctx, out);
        return `${this.funcRefDispatcherName(sig)}(${[idTmp, ...args].join(', ')})`;
      }
      case 'memField': {
        // read a value field of a memory-aggregate (struct) local: mload at ptr + offset.
        const ptr = this.ctxLookup(ctx, e.local);
        return e.wordOffset === 0 ? `mload(${ptr})` : `mload(add(${ptr}, ${e.wordOffset * 32}))`;
      }
      case 'memDynNestedField': {
        // read a leaf of a nested DYNAMIC struct (v.t.n, m.i.xs): deref the chain to the inner image, then
        // mload the final head word. A VALUE leaf (deref=false) -> the mload IS the value. A DEREF leaf
        // (deref=true: a dyn value-array field consumed via a memArrayExpr, P0-35a m.i.xs[k]) -> the mload
        // yields the head word's POINTER (to the [len][elems] image), a reference value. Both are the same
        // single mload of the head word; the deref flag only marks that the loaded word is a pointer, not a
        // scalar. A bytes/string / nested-dyn-struct deref leaf is instead consumed via lowerDynamic.
        const inner = this.nestedInnerPtr(e.local, e.derefWords, ctx, out);
        return e.finalWord === 0 ? `mload(${inner})` : `mload(add(${inner}, ${e.finalWord * 32}))`;
      }
      case 'aggFieldRead': {
        // read a field of a struct-valued Expr base (this.mk(a).x, xs[i].pre[j], xs[i].q): the field
        // pointer is the element image + static offset + runtime index steps (bounds-checked). A VALUE
        // leaf is mload'd (image stores clean values, no mask); a whole STATIC AGGREGATE leaf yields the
        // sub-image pointer (consumed as a memory aggregate by aggToMemPtr / abi.encode / return).
        const cur = this.aggFieldPtr(e.base, e.wordOffset, e.runSteps, ctx, out);
        // Residual B3: a DYNAMIC field (bytes/string/dyn value-array) of a memory-array dyn-struct
        // element - the head word at `cur` HOLDS the blob/array absolute pointer; mload it to yield
        // the pointer VALUE (a reference consumed by lowerDynamic / .length / [j] / return / encode).
        if (e.deref) return `mload(${cur})`;
        // FIX C (funcref): a funcref LEAF (h.fs[i]) is a value word (its id) stored inline, so it is
        // mload'd exactly like a static value leaf; a following funcRefCall dispatches through the id.
        // A whole STATIC AGGREGATE leaf (struct/array) yields the sub-image pointer instead.
        return isStaticValueType(e.type) || e.type.kind === 'funcref' ? `mload(${cur})` : cur;
      }
      case 'memElem': {
        // a[i] on a fixed-array memory local (value element): bounds-check then mload. A fixed-array
        // FIELD of a memory struct (p.a[i]) starts wordOffset words into the image.
        const ptr = this.ctxLookup(ctx, e.local);
        const base = e.wordOffset ? `add(${ptr}, ${e.wordOffset * 32})` : ptr;
        const i = this.fresh();
        out.push(`let ${i} := ${this.lowerExpr(e.index, ctx, out)}`);
        out.push(`if iszero(lt(${i}, ${e.length})) { ${this.panic()}(0x32) }`);
        // W6C: an ENUM element read from a fixed memory array is range-checked (Panic 0x21,
        // solc's read_from_memory) - the image may hold RAW words from the calldata bind copy.
        const enFix = this.enumCount(e.type);
        if (enFix !== undefined) {
          const w = this.fresh();
          out.push(`let ${w} := mload(add(${base}, mul(${i}, 0x20)))`);
          out.push(`if iszero(lt(${w}, ${enFix})) { ${this.panic()}(0x21) }`);
          return w;
        }
        return `mload(add(${base}, mul(${i}, 0x20)))`;
      }
      case 'memAggregate': {
        // a whole memory aggregate (the local's pointer), or a nested struct field at a word
        // offset (a sub-pointer into the parent image, which aliases it).
        const base = this.ctxLookup(ctx, e.local);
        return e.wordOffset ? `add(${base}, ${e.wordOffset * 32})` : base;
      }
      case 'global':
        return this.lowerGlobal(e);
      case 'keccak': {
        // keccak256(bytes/string): hash the CONTENT bytes (data at mp+0x20, length len).
        const { mp, len } = this.toMemory(this.lowerDynamic(e.arg, ctx, out), out);
        const r = this.fresh();
        out.push(`let ${r} := keccak256(add(${mp}, 0x20), ${len})`);
        return r;
      }
      case 'modOp': {
        // addmod/mulmod: full-precision (a op b) mod m. Solidity reverts Panic(0x12) when the
        // modulus is 0 (unlike the raw EVM opcode, which returns 0); args are evaluated first.
        const ma = this.lowerExpr(e.a, ctx, out);
        const mb = this.lowerExpr(e.b, ctx, out);
        const mm = this.fresh();
        out.push(`let ${mm} := ${this.lowerExpr(e.m, ctx, out)}`);
        out.push(`if iszero(${mm}) { ${this.panic()}(0x12) }`);
        return `${e.op}(${ma}, ${mb}, ${mm})`;
      }
      case 'abiDecode': {
        // abi.decode(data, T) / data.decode(T) with a VALUE T: the single decoded component is one
        // validated word (a reference T is lowered via lowerDynamic / the aggregate paths instead).
        return this.lowerAbiDecode(e.data, [e.type], ctx, out)[0]!;
      }
      case 'precompileHash': {
        // sha256 (0x02) / ripemd160 (0x03): staticcall the precompile over the CONTENT bytes,
        // output 32 bytes to scratch. ripemd160's 20-byte result is right-aligned, so left-shift
        // it 96 bits to the bytesN (left-aligned) register form (matches solc).
        const { mp, len } = this.toMemory(this.lowerDynamic(e.arg, ctx, out), out);
        const r = this.fresh();
        out.push(`if iszero(staticcall(gas(), ${e.addr}, add(${mp}, 0x20), ${len}, 0x00, 0x20)) { revert(0, 0) }`);
        out.push(`let ${r} := ${e.leftShift ? `shl(${e.leftShift}, mload(0x00))` : 'mload(0x00)'}`);
        return r;
      }
      case 'ecrecover': {
        // RAW solc ecrecover: staticcall(0x01) over [hash | left-padded-v | r | s] (128B) into a fresh
        // buffer; address(0) on ANY failure, NEVER reverts (the returndatasize()==0x20 guard is mandatory
        // so a failed call never leaks stale memory into the returned address).
        const hash = this.lowerExpr(e.hash, ctx, out);
        const v = this.lowerExpr(e.v, ctx, out);
        const r = this.lowerExpr(e.r, ctx, out);
        const s = this.lowerExpr(e.s, ctx, out);
        return this.emitEcrecover(hash, v, r, s, out);
      }
      case 'recover': {
        // SAFE OZ-5.x ECDSA.recover. The 65-byte bytes form reads r/s/v from the memory image of `sig`;
        // the split form uses the v/r/s registers directly. Then s>HALF (STRICT) and signer==0 checks.
        let rWord: string;
        let sWord: string;
        let vWord: string;
        const hash = this.lowerExpr(e.hash, ctx, out);
        if (e.sig) {
          const { mp, len } = this.toMemory(this.lowerDynamic(e.sig, ctx, out), out);
          // length != 65 -> ECDSAInvalidSignatureLength(uint256 length)
          out.push(`if iszero(eq(${len}, 65)) {`);
          out.push(`  mstore(0, ${ECDSA_INVALID_SIGNATURE_LENGTH})`);
          out.push(`  mstore(4, ${len})`);
          out.push('  revert(0, 0x24)');
          out.push('}');
          const rr = this.fresh();
          const ss = this.fresh();
          const vv = this.fresh();
          out.push(`let ${rr} := mload(add(${mp}, 0x20))`);
          out.push(`let ${ss} := mload(add(${mp}, 0x40))`);
          out.push(`let ${vv} := byte(0, mload(add(${mp}, 0x60)))`);
          rWord = rr;
          sWord = ss;
          vWord = vv;
        } else {
          rWord = this.lowerExpr(e.r!, ctx, out);
          sWord = this.lowerExpr(e.s!, ctx, out);
          vWord = this.lowerExpr(e.v!, ctx, out);
        }
        // s > HALF_ORDER (STRICT) -> ECDSAInvalidSignatureS(bytes32 s)
        const sReg = this.fresh();
        out.push(`let ${sReg} := ${sWord}`);
        out.push(`if gt(${sReg}, ${HALF_ORDER}) {`);
        out.push(`  mstore(0, ${ECDSA_INVALID_SIGNATURE_S})`);
        out.push(`  mstore(4, ${sReg})`);
        out.push('  revert(0, 0x24)');
        out.push('}');
        const signer = this.emitEcrecover(hash, vWord, rWord, sReg, out);
        // signer == address(0) -> ECDSAInvalidSignature() (covers bad v / out-of-range r,s)
        out.push(`if iszero(${signer}) {`);
        out.push(`  mstore(0, ${ECDSA_INVALID_SIGNATURE})`);
        out.push('  revert(0, 4)');
        out.push('}');
        return signer;
      }
      case 'bn256': {
        if (e.op === 'pairing') {
          // bn256Pairing(input): staticcall 0x08 over the packed bytes blob, read the single bool word.
          // 0x00 scratch is safe (consumed immediately like precompileHash). Reverts EMPTY on failure.
          const { mp, len } = this.toMemory(this.lowerDynamic(e.args[0]!, ctx, out), out);
          const r = this.fresh();
          out.push(`if iszero(staticcall(gas(), 8, add(${mp}, 0x20), ${len}, 0x00, 0x20)) { revert(0, 0) }`);
          out.push(`let ${r} := mload(0x00)`);
          return r;
        }
        // bn256Add(0x06) / bn256Mul(0x07): materialize each G1Point to a 2-word memory image FIRST (an
        // allocating source must not bump the FMP between the buffer alloc and the field reads), then
        // allocate a FRESH FMP buffer (NOT scratch - a 0x40 clobber OOGs), copy the input words, staticcall,
        // and the 64-byte G1Point result lands in-place at the buffer. Bump the FMP past it; the result is a
        // memAggregate-shaped 2-word memory image. Reverts EMPTY on an invalid point / bad input.
        const aPtr = this.aggArgToMemPtr(e.args[0]!, ctx, out);
        const aX = this.fresh();
        const aY = this.fresh();
        out.push(`let ${aX} := mload(${aPtr})`);
        out.push(`let ${aY} := mload(add(${aPtr}, 0x20))`);
        let bX = '';
        let bY = '';
        let scalar = '';
        if (e.op === 'add') {
          const bPtr = this.aggArgToMemPtr(e.args[1]!, ctx, out);
          bX = this.fresh();
          bY = this.fresh();
          out.push(`let ${bX} := mload(${bPtr})`);
          out.push(`let ${bY} := mload(add(${bPtr}, 0x20))`);
        } else {
          scalar = this.fresh();
          out.push(`let ${scalar} := ${this.lowerExpr(e.args[1]!, ctx, out)}`);
        }
        const p = this.fresh();
        out.push(`let ${p} := mload(0x40)`);
        out.push(`mstore(${p}, ${aX})`);
        out.push(`mstore(add(${p}, 0x20), ${aY})`);
        if (e.op === 'add') {
          out.push(`mstore(add(${p}, 0x40), ${bX})`);
          out.push(`mstore(add(${p}, 0x60), ${bY})`);
        } else {
          out.push(`mstore(add(${p}, 0x40), ${scalar})`);
        }
        const insizeHex = e.insize === 'dynamic' ? '0' : `0x${e.insize.toString(16)}`;
        out.push(`if iszero(staticcall(gas(), ${e.addr}, ${p}, ${insizeHex}, ${p}, 0x40)) { revert(0, 0) }`);
        out.push(`mstore(0x40, add(${p}, 0x40))`);
        return p;
      }
      case 'blockhash':
        return `blockhash(${this.lowerExpr(e.arg, ctx, out)})`;
      case 'blobhash':
        return `blobhash(${this.lowerExpr(e.arg, ctx, out)})`;
      case 'balance':
        return `balance(${this.lowerExpr(e.addr, ctx, out)})`;
      case 'isContract': {
        // OZ `addr.code.length > 0`: gt(extcodesize(addr), 0).
        const a = this.lowerExpr(e.addr, ctx, out);
        return `gt(extcodesize(${a}), 0)`;
      }
      case 'cloneDeploy':
        return this.lowerCloneDeploy(e, ctx, out);
      case 'predictClone':
        return this.lowerPredictClone(e, ctx, out);
      case 'proxySlotRead':
        // proxyImplementation()/proxyAdmin(): SLOAD the EIP-1967 impl/admin slot, masked to 160 bits
        // (the slot holds a right-aligned address; the high 96 bits are zero on a clean write).
        return `and(sload(${e.slot === 'admin' ? EIP1967_ADMIN_SLOT : EIP1967_IMPL_SLOT}), 0xffffffffffffffffffffffffffffffffffffffff)`;
      case 'proxyBeaconRead':
        // proxyBeacon(): SLOAD the EIP-1967 beacon slot, masked to 160 bits (a right-aligned address).
        return `and(sload(${EIP1967_BEACON_SLOT}), 0xffffffffffffffffffffffffffffffffffffffff)`;
      case 'extCode':
        // <addr>.codehash -> a single bytes32 word (EXTCODEHASH). The bytes form (<addr>.code) is a
        // reference value, lowered via lowerDynamic (it reaches the throw list below if misused).
        if (e.member === 'codehash') return `extcodehash(${this.lowerExpr(e.addr, ctx, out)})`;
        throw new UnsupportedError(`reference value '${e.kind}' used in a non-reference context`);
      case 'callOk':
        // bound only inside a .call/.staticcall success condition: the captured success bool.
        return this.ctxLookup(ctx, EXT_CALL_OK_BINDING);
      case 'catchPanic': {
        // `this.panic` inside a try/catch catch body: SOFT-decode Panic(uint256). Panic has a fixed
        // 4 + 32 layout, so the only checks are length >= 36 and the selector; never hard-revert
        // (yields 0 when the returndata is not a Panic). Byte-identical to solc's `catch Panic(uint c)`.
        const blob = this.ctxLookup(ctx, EXT_CALL_DATA_BINDING);
        const r = this.fresh();
        out.push(`let ${r} := 0`);
        out.push(`if and(iszero(lt(mload(${blob}), 36)), eq(shr(224, mload(add(${blob}, 0x20))), 0x4e487b71)) {`);
        out.push(`  ${r} := mload(add(${blob}, 0x24))`);
        out.push('}');
        return r;
      }
      case 'cast':
        return this.lowerCast(e, ctx, out);
      case 'mapGet': {
        const slot = this.mappingSlot(e.baseSlot, e.keys, ctx, out);
        return this.loadState(e.type, slot, 0);
      }
      case 'dynLength': {
        const ref = this.lowerDynamic(e.operand, ctx, out);
        return this.dynLen(ref);
      }
      case 'byteIndex':
        return this.lowerByteIndex(e, ctx, out);
      case 'arrayLen': {
        const ref = this.lowerArrayRef(e.arr, ctx, out);
        if (ref.src === 'storage') return `sload(${ref.lenSlot})`;
        if (ref.src === 'fixed') return String(ref.length);
        if (ref.src === 'memory') return ref.fixedLen !== undefined ? String(ref.fixedLen) : `mload(${ref.ptr})`;
        return ref.length;
      }
      case 'placeRead': {
        const p = this.lowerPlace(e.path, ctx, out);
        // a packed element with a RUNTIME byte offset uses packedLoad; otherwise the
        // constant-offset loadState (which also covers a literal packed index).
        if (p.byteShift !== undefined) return this.packedLoad(e.type, p.slot, p.byteShift);
        return this.loadState(e.type, p.slot, p.offset);
      }
      case 'cdPlaceRead': {
        // Read a leaf from an aggregate calldata param. solc validates lazily on
        // access: a dirty (non-canonical) word reverts empty, never masks.
        const off = this.lowerCdPlace(e.place, ctx, out);
        const w = this.fresh();
        out.push(`let ${w} := calldataload(${off})`);
        const guard = this.validateInput(e.type, w);
        if (guard) out.push(guard);
        return w;
      }
      case 'cdDynStructLeaf': {
        // Read a static-value leaf of a dynamic-struct calldata param. Lazy
        // validation: a dirty leaf word reverts empty (matches solc).
        const off = this.lowerCdDynLeafOff(e.place, ctx, out);
        const w = this.fresh();
        out.push(`let ${w} := calldataload(${off})`);
        const guard = this.validateInput(e.type, w);
        if (guard) out.push(guard);
        return w;
      }
      case 'cdArrayField': {
        // ps[i].field on a calldata dynamic array of static struct: bounds-check
        // i (Panic 0x32), then read the field's leaf word at stride*i + headWords;
        // a single read validates dirty bits (revert empty), like x[i].
        const ref = this.lowerArrayRef(e.arr, ctx, out);
        if (ref.src !== 'calldata') throw new UnsupportedError('cdArrayField requires a calldata array');
        const i = this.fresh();
        out.push(`let ${i} := ${this.lowerExpr(e.index, ctx, out)}`);
        out.push(`if iszero(lt(${i}, ${ref.length})) { ${this.panic()}(0x32) }`);
        const stride = abiHeadWords(e.arr.elem) * 32;
        const disp = e.headWords * 32;
        // ps[i].xs[j]: a fixed value-array FIELD element. Each element is one ABI head
        // word (inline in the struct head); bound j against N (Panic 0x32) then add
        // j*32 to the field displacement. solc checks the outer i bound first.
        if (e.elemIndex !== undefined) {
          const j = this.fresh();
          out.push(`let ${j} := ${this.lowerExpr(e.elemIndex, ctx, out)}`);
          out.push(`if iszero(lt(${j}, ${e.elemLength})) { ${this.panic()}(0x32) }`);
          const at2 =
            disp === 0
              ? `add(mul(${i}, ${stride}), mul(${j}, 0x20))`
              : `add(add(mul(${i}, ${stride}), ${disp}), mul(${j}, 0x20))`;
          const w2 = this.fresh();
          out.push(`let ${w2} := calldataload(add(${ref.offset}, ${at2}))`);
          const g2 = this.validateInput(e.fieldType, w2);
          if (g2) out.push(g2);
          return w2;
        }
        const at = disp === 0 ? `mul(${i}, ${stride})` : `add(mul(${i}, ${stride}), ${disp})`;
        const w = this.fresh();
        out.push(`let ${w} := calldataload(add(${ref.offset}, ${at}))`);
        const guard = this.validateInput(e.fieldType, w);
        if (guard) out.push(guard);
        return w;
      }
      case 'arrayGet':
        return this.lowerArrayGet(e, ctx, out);
      case 'arrayLit': {
        // a NESTED value array (u256[][], Arr<u256[],2>, ...): build JETH's nested image (dynamic
        // outer = [len][inline static blocks | absolute pointers]; fixed-of-dynamic outer = N pointer
        // words). A pure-static nested array (Arr<Arr<u256,2>,2>) goes through the memAggregate /
        // arrayLit-static path elsewhere (its image is inline words), so only the dynamic-bearing
        // nestings dispatch here.
        // also a Residual-B aggregate-leaf array (P[] static struct, bytes[]/string[]): the codec lays
        // out an inline struct block per element, or an absolute blob pointer per bytes/string element.
        if (
          // isNestedValueWordArray also admits a nested FUNCREF-leaf array bearing a DYNAMIC level
          // (((x)=>R)[][], Arr<(x)=>R,2>[], Arr<((x)=>R)[],N>): the funcref leaf is one value word, so the
          // codec lays it out exactly like the u256-substituted shape. A PURE-FIXED nested funcref array
          // (Arr<Arr<(x)=>R,2>,2>) is fully inline and stays on the allocAggToMem path (isDynamicType false).
          (isNestedValueWordArray(e.type) && isDynamicType(e.type)) ||
          isAggregateLeafArray(e.type) ||
          isStaticStructFixedLeafArray(e.type) || // Batch A: Arr<P,N>, Arr<Arr<P,N>,M>, Arr<P,N>[][]... fixed outer
          isDynBytesFixedLeafArray(e.type) || // Edge D: Arr<string,N>, Arr<bytes,N> fixed-outer bytes/string leaf
          (isStaticStructAnyLeafArray(e.type) && isDynamicType(e.type)) // Arr<P,N>[] dynamic outer
        ) {
          return this.buildNestedMemArrayLit(e, ctx, out);
        }
        // a MEMORY T[] (value elements): build [len][e0][e1]...] at the free pointer; the
        // register value IS the pointer. (The ABI-return form is handled by encodeArrayReturn.)
        // FREEZE each element into a register FIRST (left-to-right): an element may be a call that
        // itself allocates memory via mload(0x40), so its allocation must bump the free pointer
        // BEFORE we claim the array region - otherwise the callee overwrites the array.
        const vals = e.elements.map((el) => {
          const r = this.fresh();
          out.push(`let ${r} := ${this.lowerExpr(el, ctx, out)}`);
          return r;
        });
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(0x40)`);
        out.push(`mstore(${ptr}, ${vals.length})`);
        vals.forEach((v, i) => out.push(`mstore(add(${ptr}, ${(i + 1) * 32}), ${v})`));
        out.push(`mstore(0x40, add(${ptr}, ${(vals.length + 1) * 32}))`);
        return ptr;
      }
      case 'newArray': {
        // new Array<E>(n) where E is itself an array (u256[][] = new Array<u256[]>(n), ...), a STATIC
        // STRUCT (Residual B1: new Array<P>(n) -> n inline all-zero P images), or bytes/string
        // (Residual B2: new Array<bytes>(n) -> n pointers to fresh EMPTY [0] blobs): a length-n outer
        // image with each element zero-initialized exactly as solc does (an empty inner / blob, or a
        // zero struct block).
        if (e.elem.kind === 'array' || e.elem.kind === 'struct' || isBytesLike(e.elem)) {
          return this.zeroInitNestedMemArray(e.type as JethType & { kind: 'array' }, this.lowerExpr(e.length, ctx, out), ctx, out);
        }
        // new Array<T>(n) -> a length-n zero-initialized memory T[] ([len][n words], one full word
        // per value element - memory arrays are never packed). Byte-identical to solc new T[](n):
        // cap the element count at 2^64-1 (Panic 0x41, matching solc's deterministic overflow guard,
        // which also keeps the allocation from wrapping), then ACTIVELY zero the data region so the
        // result is all-zero even over dirty memory exactly as solc guarantees (calldatacopy reading
        // past calldatasize writes zeros) - do not rely on the memory beyond the free pointer being
        // clean. Lower the length BEFORE claiming mload(0x40) so a side-effecting length that itself
        // allocates bumps the free pointer first.
        const n = this.fresh();
        out.push(`let ${n} := ${this.lowerExpr(e.length, ctx, out)}`);
        out.push(`if gt(${n}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(0x40)`);
        out.push(`mstore(${ptr}, ${n})`);
        out.push(`calldatacopy(add(${ptr}, 0x20), calldatasize(), mul(${n}, 0x20))`);
        out.push(`mstore(0x40, add(${ptr}, mul(add(${n}, 1), 0x20)))`);
        return ptr;
      }
      case 'arrayValue':
        // a memory array's register value IS its pointer (used when a memArray flows
        // through a ternary or a local-array assignment). Other array sources are
        // reference values consumed by the return/assign/length/index paths.
        if (e.arr.base.kind === 'memArray') return this.ctxLookup(ctx, e.arr.base.varName);
        throw new UnsupportedError(`reference value '${e.kind}' used in a non-reference context`);
      case 'dynStateRead':
      case 'dynParamRead':
      case 'msgData':
      case 'calldataSlice':
      case 'dynLocalRead':
      case 'memDynField':
      case 'memDynStructValue':
      case 'cdDynArrayElem':
      case 'strArrayElem':
      case 'dynPlaceRead':
      case 'cdDynStructField':
      case 'cdDynStructValue':
      case 'cdAggregateValue':
      case 'stringLiteral':
      case 'structNew':
      case 'structValue':
      case 'structArrayElem':
      case 'cdStructArrayElem':
      case 'cdAggArrayElem':
      case 'cdFieldAggValue': // whole dyn-array field of a cd struct-array element: return path / aggArgToMemPtr
      case 'cdNestedFieldAggValue': // whole inner array of such a nested field: return path / aggArgToMemPtr
      case 'cdPlaceReadAgg': // S4: whole static-aggregate leaf of a static calldata param: aggToMemPtr / return / abi.encode
      case 'mapStorageValue':
      case 'mapDynValue':
      case 'abiEncode':
      case 'modexp': // modexp(...) -> bytes (a reference value, lowered via lowerDynamic)
      case 'blake2f': // blake2f(...) -> 64-byte bytes (a reference value, lowered via lowerDynamic)
      case 'extCall': // bytes returndata (a reference value, lowered via lowerDynamic)
      case 'cloneArgs': // cloneArgs() -> bytes (this clone's immutable args, lowered via lowerDynamic)
      case 'callData': // this.data inside a success condition (the returndata bytes reference)
      case 'catchReason': // this.reason (string) inside a catch body (a reference value, lowered via lowerDynamic)
      case 'proxyInit': // void EIP-1967 statement: lowered in exprStmt via lowerProxyMutate (never a value)
      case 'upgradeProxy': // void EIP-1967 statement: lowered in exprStmt via lowerProxyMutate (never a value)
      case 'proxyInitBeacon': // void EIP-1967 BEACON statement: lowered in exprStmt (never a value)
      case 'diamondInit': // void diamond ctor primitive: lowered in exprStmt via lowerDiamondInit
      case 'diamondInitSolidstate': // void solidstate diamond ctor primitive: lowered in exprStmt
      case 'diamondDelegateInit': // void diamond statement: lowered in exprStmt (never a value)
      case 'diamondCutPacked': // void diamond-2 cut: lowered in exprStmt via lowerDiamondCutPacked
      case 'diamondCutSolidstate': // void solidstate diamond-2 cut: lowered in exprStmt
      case 'revertSelector': // void custom-error revert: lowered in exprStmt
      case 'diamondFacets': // Facet[] aggregate: consumed by the return path (lowerDiamondFacetsReturn)
      case 'diamondFacetsPacked': // Facet[] aggregate: consumed by the return path (packed loupe)
      case 'diamondFacetSelectorsPacked': // bytes4[] aggregate: consumed by the return path (packed loupe)
      case 'diamondFacetAddressesPacked': // address[] aggregate: consumed by the return path (packed loupe)
        // reference/aggregate values are not single 256-bit words; they are
        // consumed by the return/assign/length/index paths.
        throw new UnsupportedError(`reference value '${e.kind}' used in a non-reference context`);
    }
  }

  /** Encode a static struct value into ABI head words at memory 0; returns the size. */
  private encodeStructReturn(value: Expr, ctx: LowerCtx, out: string[]): number {
    if (value.kind === 'structValue') {
      const fields = (value.type as JethType & { kind: 'struct' }).fields;
      fields.forEach((f, j) => {
        const w = this.loadState(f.type, String(value.baseSlot + BigInt(f.slot)), f.offset);
        out.push(`mstore(${j * 32}, ${w})`);
      });
      return fields.length * 32;
    }
    if (value.kind === 'structNew') {
      // ABI head, one word per leaf: value fields write one word; a fixed-array-literal
      // field writes its N elements at consecutive head words.
      let w = 0;
      value.fields.forEach((f, j) => {
        const arg = value.args[j]!;
        if (f.type.kind === 'array' && arg.kind === 'arrayLit') {
          this.encodeArrayLitHead(arg, w, ctx, out);
          w += abiHeadWords(f.type);
        } else if (
          (f.type.kind === 'struct' || (f.type.kind === 'array' && f.type.length !== undefined)) &&
          arg.kind === 'structNew'
        ) {
          // a nested inline static struct field (Outer(id, Inner(...))): flatten its leaf words
          // inline at consecutive head words, recursing into deeper nested structs.
          this.staticNewLeaves(f.type, arg, ctx, out).forEach((lw, k) => out.push(`mstore(${(w + k) * 32}, ${lw})`));
          w += abiHeadWords(f.type);
        } else {
          out.push(`mstore(${w * 32}, ${this.lowerExpr(arg, ctx, out)})`);
          w += abiHeadWords(f.type);
        }
      });
      return w * 32;
    }
    if (value.kind === 'abiDecode') {
      // a STATIC struct decoded from a blob (return abi.decode(b, P)) or returned by an @external
      // (delegatecall) @library function whose result is decoded as a struct (return L.mk(a)).
      // lowerAbiDecode builds the flat inline static-struct image (abiHeadWords words, with solc's
      // decode revert semantics on malformed input); copy it to the memory-0 return scratch. Without
      // this the abiDecode struct fell through and threw (cannot encode struct from abiDecode).
      const mp = this.lowerAbiDecode(value.data, [value.type], ctx, out)[0]!;
      const w = abiHeadWords(value.type);
      out.push(`mcopy(0, ${mp}, ${w * 32})`);
      return w * 32;
    }
    throw new UnsupportedError(`cannot encode struct from ${value.kind}`);
  }

  /** Flatten a (possibly NESTED) static array literal into ABI head words starting at head
   *  word `wordBase` (memory offset wordBase*32). Value elements write one word; nested
   *  array / struct-literal elements recurse at wordBase + k*abiHeadWords(element). */
  private encodeArrayLitHead(lit: Expr & { kind: 'arrayLit' }, wordBase: number, ctx: LowerCtx, out: string[]): void {
    const elem = lit.elem;
    const ew = abiHeadWords(elem);
    lit.elements.forEach((el, k) => {
      const wb = wordBase + k * ew;
      if (el.kind === 'arrayLit') this.encodeArrayLitHead(el, wb, ctx, out);
      else if (el.kind === 'structNew') {
        // a struct-literal element: write each field as head word(s). A fixed-array subfield recurses;
        // a nested inline static struct subfield is flattened to its leaf words; a value subfield is one word.
        let fw = wb;
        el.fields.forEach((sf, sj) => {
          const sarg = el.args[sj]!;
          if (sf.type.kind === 'array' && sarg.kind === 'arrayLit') {
            this.encodeArrayLitHead(sarg, fw, ctx, out);
            fw += abiHeadWords(sf.type);
          } else if (
            (sf.type.kind === 'struct' || (sf.type.kind === 'array' && sf.type.length !== undefined)) &&
            sarg.kind === 'structNew'
          ) {
            this.staticNewLeaves(sf.type, sarg, ctx, out).forEach((lw, k) =>
              out.push(`mstore(${(fw + k) * 32}, ${lw})`),
            );
            fw += abiHeadWords(sf.type);
          } else {
            out.push(`mstore(${fw * 32}, ${this.lowerExpr(sarg, ctx, out)})`);
            fw += abiHeadWords(sf.type);
          }
        });
      } else out.push(`mstore(${wb * 32}, ${this.lowerExpr(el, ctx, out)})`);
    });
  }

  /** Encode a MULTI-VALUE return `return [a, b, ...]` as a top-level ABI tuple (head/tail,
   *  NO outer offset wrapper - unlike a single dynamic value/struct return). Components may
   *  be a value (one inline head word), bytes/string (offset word + tail), or a storage-
   *  source struct/array (static -> inline head words; dynamic -> offset word + tail, via
   *  the recursive storage encoder). bytes/string sources are materialized BEFORE the blob
   *  pointer is captured so a later allocation cannot alias the blob. */
  private encodeReturnTuple(
    values: Expr[],
    types: JethType[],
    ctx: LowerCtx,
    out: string[],
  ): { ptr: string; size: string } {
    // W6A: an EXTERNAL multi-return is ABI-encoded to returndata immediately - a TRANSIENT capture
    // context (internal returnTuple takes the fnMode path and never reaches here).
    return this.inTransientCapture(() => this.encodeReturnTupleInner(values, types, ctx, out));
  }

  private encodeReturnTupleInner(
    values: Expr[],
    types: JethType[],
    ctx: LowerCtx,
    out: string[],
  ): { ptr: string; size: string } {
    // ---- W7A PHASE 1 (source order): evaluate every component to a value local or a reference
    // handle. All user side effects run here, left-to-right - the former five PRE-PASSES each
    // hoisted one component KIND ahead of every sibling (bytes/literal/ternary-array/dyn-struct-
    // ctor/cd-field), and static values / storage reads ran late inside the write loop; both
    // reorderings diverged from solc's two-phase model (probes P14-P21). Serialization happens
    // below, reading through the handles LATE (memory aliases see sibling mutations; storage
    // components re-read post-sibling storage - probes P3/P4/P19).
    const refs: (DynRef | null)[] = types.map(() => null); // bytes/string reference (materialized in 2a)
    const words: (string | null)[] = types.map(() => null); // spilled static-value locals
    const memExprRefs: (string | null)[] = types.map(() => null); // memArrayExpr image pointers
    const litRefs: (string | null)[] = types.map(() => null); // inline value-array literal images
    const cdFieldHdr: (string | null)[] = types.map(() => null); // calldata dyn-field headers
    const staticNewPtr: (string | null)[] = types.map(() => null); // static structNew flat images (+patches)
    const dynNewSrc: (TupleSrc | null)[] = types.map(() => null); // dyn structNew pointer-headed handles
    const dynStructRefs: ({ mp: string; size: string } | null)[] = types.map(() => null); // dyn structNew fallback blobs
    const storSlot: (string | null)[] = types.map(() => null); // frozen storage base slots
    const prevPatches = this.beginTwoPhase();
    types.forEach((t, i) => {
      const v = values[i]!;
      if (isBytesLike(t)) {
        refs[i] = this.lowerDynamic(v, ctx, out);
      } else if (isStaticValueType(t)) {
        const w = this.fresh();
        out.push(`let ${w} := ${this.lowerExpr(v, ctx, out)}`);
        words[i] = w;
      } else if (
        t.kind === 'array' &&
        v.kind === 'arrayValue' &&
        (v.arr.base.kind === 'memArray' || v.arr.base.kind === 'memArrayExpr')
      ) {
        if (v.arr.base.kind === 'memArrayExpr') {
          const p = this.fresh();
          out.push(`let ${p} := ${this.lowerExpr(v.arr.base.expr, ctx, out)}`);
          memExprRefs[i] = p;
        } // a memArray local resolves at write time (a pure register lookup, no code)
      } else if (t.kind === 'array' && t.length === undefined && isStaticValueType(t.element) && v.kind === 'arrayLit') {
        // an inline value-array literal: element values evaluate at the component's position
        // (value semantics); the fresh image is unreachable by siblings, so encode-late == now.
        litRefs[i] = this.lowerExpr(v, ctx, out);
      } else if (v.kind === 'cdFieldAggValue' || v.kind === 'cdNestedFieldAggValue') {
        // the calldata header resolves at position (index side effects, Panic 0x32); the
        // deep-copy + validation runs in phase 2a (immutable source, late validation flavors).
        cdFieldHdr[i] =
          v.kind === 'cdFieldAggValue'
            ? this.cdFieldArrayHeader(v.place, ctx, out)
            : this.cdNestedFieldArrayHeader(v.place, v.indices, ctx, out);
      } else if (this.staticCdComponentName(v, t) || this.cdComponentName(v)) {
        // whole calldata params: immutable, no position effects; the validating encode runs in
        // the write loop (late), unchanged.
      } else if (!isDynamicType(t) && v.kind === 'structNew') {
        // a constructed STATIC struct: freeze its flat image at position (args evaluate now, in
        // order; live memory-ref args record capture patches re-copied after phase 1).
        staticNewPtr[i] = this.allocAggToMem(v, ctx, out);
      } else if (!isDynamicType(t) && v.kind === 'memAggregate') {
        // a static memory local: a pure register alias, resolved at write time (mcopy reads late).
      } else if (isDynamicType(t) && t.kind === 'struct' && v.kind === 'structNew') {
        if (this.dynStructMemSrcEncodable(t)) {
          // build the native pointer-headed image at position (args in order, refs captured as
          // pointers, static-agg fields patched); the write loop encodes from it LATE.
          dynNewSrc[i] = { kind: 'mem', headPtr: this.buildDynStructLocal(t, v, ctx, out) };
        } else {
          // rare field shapes the mem-src encoder cannot serialize: keep the at-position blob
          // (pre-two-phase behavior, now at the component's source position instead of a pre-pass).
          dynStructRefs[i] = this.encodeDynStructToBlob(v, ctx, out);
        }
      } else if (isDynamicType(t) && t.kind === 'struct' && v.kind === 'memDynStructValue') {
        // a dyn-struct memory local: resolved + encoded at write time through its image pointer.
      } else {
        // a storage-source component: freeze the base slot at position (mapping keys / indices /
        // bounds checks run now); the storage->returndata encode runs at write time (LATE reads,
        // matching solc - probes P3/P4/P19).
        storSlot[i] = this.aggComponentSlot(v, ctx, out);
      }
    });
    this.flushTwoPhase(prevPatches, out);
    // ---- PHASE 2a: materialize the bytes/string references and calldata-field images (all
    // allocation happens HERE, before the tuple pointer is captured, so nothing can alias the
    // blob; all reads are post-side-effect). ----
    const refMat: ({ mp: string; len: string } | null)[] = refs.map((r) => (r ? this.toMemory(r, out) : null));
    const cdFieldRefs: (string | null)[] = values.map((v, i) => {
      if (!cdFieldHdr[i]) return null;
      return this.abiDecFromCdToImage(v.type, cdFieldHdr[i]!, out, `${this.panic()}(0x41)`);
    });
    const headWordsOf = (t: JethType): number => (isDynamicType(t) ? 1 : abiHeadWords(t));
    const totalHead = types.reduce((n, t) => n + headWordsOf(t), 0);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    const cursor = this.fresh();
    out.push(`let ${cursor} := add(${ptr}, ${totalHead * 32})`);
    // W6B (tuple-return-alloc-clobber): reserve the buffer built so far ([ptr, cursor)) BEFORE
    // evaluating a component expression inside the loop. An ALLOCATING later component
    // (keccak256(abi.encode(x)), an internal call, a ternary hash, a struct-field aggToMemPtr)
    // grabs mload(0x40) - which still pointed at `ptr` - and its scratch blob clobbered the
    // EARLIER head words already written (word0 became the blob's length word, 0x20). Bumping
    // 0x40 to the tail frontier makes the scratch land ABOVE everything written; a subsequent
    // tail write may overwrite that dead scratch, which is harmless (the component's value is
    // already in a register). The epilogue mstore(0x40, cursor) re-tightens the frontier, and
    // evaluation ORDER is unchanged (a pre-pass would reorder side effects vs the storage-
    // encoded components).
    const reserve = (): void => {
      out.push(`mstore(0x40, ${cursor})`);
    };
    let hw = 0;
    types.forEach((t, i) => {
      const headPos = hw * 32;
      if (isBytesLike(t)) {
        const { mp, len } = refMat[i]!;
        const padded = `and(add(${len}, 0x1f), not(0x1f))`;
        out.push(`mstore(add(${ptr}, ${headPos}), sub(${cursor}, ${ptr}))`);
        out.push(`mcopy(${cursor}, ${mp}, add(0x20, ${padded}))`); // [len][data] from mp
        out.push(`${cursor} := add(${cursor}, add(0x20, ${padded}))`);
        hw += 1;
      } else if (isStaticValueType(t)) {
        // W7A: the value was spilled at its source position in phase 1; just store it.
        out.push(`mstore(add(${ptr}, ${headPos}), ${words[i]!})`);
        hw += 1;
      } else if (
        t.kind === 'array' &&
        values[i]!.kind === 'arrayValue' &&
        ((values[i] as Expr & { kind: 'arrayValue' }).arr.base.kind === 'memArray' ||
          (values[i] as Expr & { kind: 'arrayValue' }).arr.base.kind === 'memArrayExpr')
      ) {
        // a MEMORY array component (return [xs, n]).
        const av = values[i] as Expr & { kind: 'arrayValue' };
        const mp = av.arr.base.kind === 'memArray' ? this.ctxLookup(ctx, av.arr.base.varName) : memExprRefs[i]!;
        if (!isDynamicType(t)) {
          // an ABI-STATIC fixed-array ELEMENT component (return [x, m[i]] where m[i]: Arr<In,N> /
          // Arr<u256,N>, reached as an arrayValue over a memArrayExpr): ABI-static, so it is encoded
          // INLINE in the head (abiHeadWords(t) words, NO offset word) - totalHead already reserves
          // them (headWordsOf). The sibling of the e33d131 plain-local fix: writing an offset word
          // here mislocated the tail and left zero head words (the 9th pointer-headed consumer
          // miscompile). abiEncFromMem dereferences a pointer-headed Arr<In,N> element image (Batch A)
          // and copies a flat value-array image verbatim, matching the solo-return / abi.encode paths.
          this.abiEncFromMem(t, mp, `add(${ptr}, ${headPos})`, ctx, out);
          hw += abiHeadWords(t);
          return;
        }
        out.push(`mstore(add(${ptr}, ${headPos}), sub(${cursor}, ${ptr}))`);
        if (t.length === undefined && isStaticValueType(t.element)) {
          // a FLAT value array (u256[], address[], ...): the memory [len][data] IS the ABI layout
          // (one word per element), so copy it verbatim. W6C: an ENUM component is range-checked
          // first (Panic 0x21) - the image may hold RAW dirty words from a calldata bind copy.
          this.validateEnumMemArray(t, mp, out);
          const total = `mul(add(mload(${mp}), 1), 0x20)`;
          out.push(`mcopy(${cursor}, ${mp}, ${total})`);
          out.push(`${cursor} := add(${cursor}, ${total})`);
        } else {
          // a STATIC-STRUCT array (P[]: image == ABI but the stride is abiHeadWords(P), not one word),
          // a bytes[]/string[] (pointer-headed image, NOT the ABI layout), or a NESTED array (u256[][]:
          // pointer-headed): reconstruct the ABI tail from the memory image via the recursive codec -
          // the SAME encoder the single-return `return xs` path uses. A verbatim mcopy would truncate
          // the struct array (wrong stride) and corrupt the pointer-headed shapes.
          const sz = this.abiEncFromMem(t, mp, cursor, ctx, out);
          out.push(`${cursor} := add(${cursor}, ${sz})`);
        }
        hw += 1;
      } else if (litRefs[i]) {
        // an INLINE dynamic value-array literal component (return [x, [7,8,9]]): the literal was
        // materialized to a fresh [len][data] memory image in the PRE-PASS (before the blob ptr was
        // captured, so it cannot alias the blob), then encoded like a memory value-array local
        // (offset word + one-word-per-element mcopy).
        const mp = litRefs[i]!;
        out.push(`mstore(add(${ptr}, ${headPos}), sub(${cursor}, ${ptr}))`);
        const total = `mul(add(mload(${mp}), 1), 0x20)`;
        out.push(`mcopy(${cursor}, ${mp}, ${total})`);
        out.push(`${cursor} := add(${cursor}, ${total})`);
        hw += 1;
      } else if (cdFieldRefs[i]) {
        // a WHOLE calldata-field-array component (xs[i].grid / xs[i].grid[j]) deep-copied to a memory
        // image in the pre-pass: offset word + re-encode the image into the tail via abiEncFromMem (the
        // recursive codec follows the pointer-headed image; a value/struct/bytes leaf is flattened
        // exactly like the memArray-component / single-return path).
        const mp = cdFieldRefs[i]!;
        out.push(`mstore(add(${ptr}, ${headPos}), sub(${cursor}, ${ptr}))`);
        const sz = this.abiEncFromMem(t, mp, cursor, ctx, out);
        out.push(`${cursor} := add(${cursor}, ${sz})`);
        hw += 1;
      } else if (this.staticCdComponentName(values[i]!, t)) {
        // a whole STATIC calldata aggregate param (Arr<T,N> / static struct): INLINE in the head
        // (no offset word), like the storage static case. Masks value-leaf fixed arrays / validates
        // struct fields, matching solc's return decode-to-memory.
        const name = this.staticCdComponentName(values[i]!, t)!;
        const ph = ctx.cdParamHead.get(name);
        if (!ph) throw new UnsupportedError(`unbound calldata component '${name}'`);
        const leaf = (ty: JethType): JethType =>
          ty.kind === 'array' && ty.length !== undefined ? leaf(ty.element) : ty;
        const validate = !(t.kind === 'array' && isStaticValueType(leaf(t)));
        this.abiEncFromCd(t, String(ph.head), `add(${ptr}, ${headPos})`, validate, out);
        hw += abiHeadWords(t);
      } else if (this.cdComponentName(values[i]!)) {
        // a whole DYNAMIC calldata param component (return [xs, n] / [dynStructParam, n]):
        // offset word + tail via the recursive calldata encoder. The offset bounds check and
        // data-pointer resolution mirror echoParam; a flat value array cleans dirty elements,
        // everything else validates (matching solc).
        const name = this.cdComponentName(values[i]!)!;
        const ph = ctx.cdParamHead.get(name);
        if (!ph) throw new UnsupportedError(`unbound calldata component '${name}'`);
        const off = this.fresh();
        out.push(`let ${off} := calldataload(${ph.head})`);
        out.push(`if iszero(slt(${off}, sub(sub(calldatasize(), 4), 0x1f))) { revert(0, 0) }`);
        const cdPtr = this.fresh();
        out.push(`let ${cdPtr} := add(4, ${off})`);
        out.push(`mstore(add(${ptr}, ${hw * 32}), sub(${cursor}, ${ptr}))`);
        const topClean = t.kind === 'array' && t.length === undefined && isStaticValueType(t.element);
        const sz = this.abiEncFromCd(t, cdPtr, cursor, !topClean, out);
        out.push(`${cursor} := add(${cursor}, ${sz})`);
        hw += 1;
      } else if (!isDynamicType(t) && values[i]!.kind === 'structNew') {
        // a constructed STATIC struct component (return [x, P(1,2), y]): its flat image was frozen
        // at the component's source position in phase 1 (capture patches re-copied any live memory
        // ref after all sibling effects); mcopy it inline into the tuple head.
        out.push(`mcopy(add(${ptr}, ${headPos}), ${staticNewPtr[i]!}, ${abiHeadWords(t) * 32})`);
        hw += abiHeadWords(t);
      } else if (!isDynamicType(t) && values[i]!.kind === 'memAggregate') {
        // a STATIC memory struct/fixed-array local component: encoded INLINE in the head (no offset
        // word) - it is ABI-static (isDynamicType === false), so abiHeadWords(t) head words, matching
        // the solo-return / abi.encode inline layout and solc's `return (x, agg)` decode-to-memory.
        const mp = this.lowerExpr(values[i]!, ctx, out);
        if (isStaticStructFixedLeafArray(t)) {
          // Batch A: a fixed-array-of-STATIC-struct local (Arr<In,N>, Arr<Arr<In,N>,M>) is ABI-static
          // but POINTER-HEADED in memory (N absolute-pointer words -> per-element struct images). A
          // verbatim mcopy would emit the pointer words (0x80, 0xc0, ...) then drop the struct payload
          // (7,8,9,10) - the pre-existing tuple-return MISCOMPILE. Flatten each element's image inline
          // via the recursive memory codec (the SAME abiEncFromMem the solo-return path uses); it lays
          // the struct words contiguously with no offsets/length, returning abiHeadWords(t)*32 bytes.
          this.abiEncFromMem(t, mp, `add(${ptr}, ${headPos})`, ctx, out);
        } else {
          // a static memory STRUCT or a fixed VALUE array (Arr<u256,N>): the image IS the ABI head
          // layout (flat words), so a pure register-alias mcopy reads the live image LATE (probe P20).
          out.push(`mcopy(add(${ptr}, ${headPos}), ${mp}, ${abiHeadWords(t) * 32})`);
        }
        hw += abiHeadWords(t);
      } else if (dynStructRefs[i]) {
        // an INLINE-constructed DYNAMIC struct component the mem-src encoder cannot serialize:
        // offset word + the ABI blob materialized at the component's position in phase 1.
        const { mp, size } = dynStructRefs[i]!;
        out.push(`mstore(add(${ptr}, ${headPos}), sub(${cursor}, ${ptr}))`);
        out.push(`mcopy(${cursor}, ${mp}, ${size})`);
        out.push(`${cursor} := add(${cursor}, ${size})`);
        hw += 1;
      } else if (
        dynNewSrc[i] ||
        (isDynamicType(t) && t.kind === 'struct' && values[i]!.kind === 'memDynStructValue')
      ) {
        // a DYNAMIC struct component from a pointer-headed memory image (a memory local, or an
        // inline constructor whose native image was built at its position in phase 1): offset word
        // + bare tuple head/tail encoded in-place at the cursor, reading through the image LATE
        // (sibling mutations through captured references are visible - probes A3/P21). The
        // collectTupleDyn pre-pass allocates NOTHING here (materializeFixedTails = false: the tuple
        // pointer is already captured; field pointers resolve with bare mloads).
        out.push(`mstore(add(${ptr}, ${headPos}), sub(${cursor}, ${ptr}))`);
        const src = dynNewSrc[i] ?? this.tupleSrc(values[i]!, ctx, out);
        const queue: DynRef[] = [];
        this.collectTupleDyn(t as JethType & { kind: 'struct' }, src, queue, ctx, out, false);
        let qi = 0;
        const end = this.encodeTupleInto(t as JethType & { kind: 'struct' }, src, cursor, ctx, out, () => queue[qi++]!);
        out.push(`${cursor} := ${end}`);
        hw += 1;
      } else {
        // a struct / array component, storage-source: static -> inline head; dynamic ->
        // offset word + tail (both via the recursive storage encoder). The base slot was frozen at
        // the component's source position in phase 1; the sloads here read post-sibling storage
        // (probes P3/P4/P19 - solc's late storage read). W6B: reserve() keeps any internal scratch
        // above the written buffer.
        reserve();
        const slot = storSlot[i]!;
        if (isDynamicType(t)) {
          out.push(`mstore(add(${ptr}, ${headPos}), sub(${cursor}, ${ptr}))`);
          const sz = this.abiEncFromStorage(t, slot, 0, cursor, out);
          out.push(`${cursor} := add(${cursor}, ${sz})`);
          hw += 1;
        } else {
          this.abiEncFromStorage(t, slot, 0, `add(${ptr}, ${headPos})`, out);
          hw += abiHeadWords(t);
        }
      }
    });
    out.push(`mstore(0x40, ${cursor})`);
    return { ptr, size: `sub(${cursor}, ${ptr})` };
  }

  /** The calldata PARAM name of a whole dynamic calldata aggregate value (a calldata array
   *  or dynamic-struct param) used as a multi-return component, else undefined. */
  private cdComponentName(value: Expr): string | undefined {
    if (value.kind === 'arrayValue' && value.arr.base.kind === 'calldataArray') return value.arr.base.name;
    if (value.kind === 'cdDynStructValue') return value.param;
    return undefined;
  }

  /** The calldata PARAM name of a whole STATIC calldata aggregate value (a static fixed-array param
   *  -> arrayValue{calldataArray}, or a static struct param -> cdAggregateValue) used as a
   *  multi-return component, else undefined. The component is encoded INLINE in the tuple head. */
  private staticCdComponentName(value: Expr, t: JethType): string | undefined {
    if (value.kind === 'cdAggregateValue') return value.param;
    if (value.kind === 'arrayValue' && value.arr.base.kind === 'calldataArray' && !isDynamicType(t))
      return value.arr.base.name;
    return undefined;
  }

  /** Storage base slot (length slot for an array) of a storage-source aggregate value used
   *  as a multi-return component (this.d / this.m[k] / this.recs[i] / this.arr). */
  private aggComponentSlot(value: Expr, ctx: LowerCtx, out: string[]): string {
    if (value.kind === 'structValue') return String(value.baseSlot);
    if (value.kind === 'mapStorageValue') return this.mappingSlot(value.baseSlot, value.keys, ctx, out);
    if (value.kind === 'structArrayElem') return this.structArrayElemSlot(value.arr, value.index, ctx, out);
    if (value.kind === 'placeRead') return this.lowerPlace(value.path, ctx, out).slot;
    if (value.kind === 'arrayValue') {
      if (value.arr.base.kind === 'stateArray') return String(value.arr.base.slot);
      if (value.arr.base.kind === 'fixedArray') return String(value.arr.base.baseSlot);
      if (value.arr.base.kind === 'mapArray')
        return this.mappingSlot(value.arr.base.baseSlot, value.arr.base.keys, ctx, out);
      if (value.arr.base.kind === 'placeArray') return this.lowerPlace(value.arr.base.path, ctx, out).slot;
    }
    throw new UnsupportedError(
      `a multi-return ${value.type.kind} component must be a storage value (this.x / this.m[k] / this.arr[i])`,
    );
  }

  /** Encode a DYNAMIC struct return value (Phase 4e-6): sole return is
   *  [head 0x20][tuple head/tail at byte 0x20]. The value source is either a
   *  constructed struct (structNew) or a calldata dynamic-struct echo
   *  (cdDynStructValue). Returns the (ptr, size) of the encoded blob. */
  private encodeDynStructReturn(value: Expr, ctx: LowerCtx, out: string[]): { ptr: string; size: string } {
    const struct = value.type as JethType & { kind: 'struct' };
    const src = this.tupleSrc(value, ctx, out);
    // PRE-PASS: materialize every bytes/string field value into a memory/calldata
    // DynRef FIRST (string literals alloc now, below the output blob), so the blob
    // pointer captured next is past them and no later alloc can alias the blob.
    const queue: DynRef[] = [];
    this.collectTupleDyn(struct, src, queue, ctx, out);
    let qi = 0;
    const nextRef = (): DynRef => queue[qi++]!;
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`); // sole-return head offset
    const tuplePtr = this.fresh();
    out.push(`let ${tuplePtr} := add(${ptr}, 0x20)`); // tuple start (memory base)
    const end = this.encodeTupleInto(struct, src, tuplePtr, ctx, out, nextRef);
    out.push(`mstore(0x40, ${end})`); // bump free-mem pointer past the blob
    return { ptr, size: `sub(${end}, ${ptr})` };
  }

  /** Encode a DYNAMIC struct value to its bare ABI tuple head/tail blob (no leading sole-return
   *  offset), for use as a tuple COMPONENT (event data / abi.encode): the component is a head offset
   *  word + this blob in the tail. Returns the blob {mp, size}. Mirrors encodeDynStructReturn's
   *  pre-pass + encodeTupleInto sequence. */
  private encodeDynStructToBlob(value: Expr, ctx: LowerCtx, out: string[]): { mp: string; size: string } {
    const struct = value.type as JethType & { kind: 'struct' };
    // Cat C: a STORAGE struct (this.s -> structValue) with a NESTED-DYNAMIC-LEAF array field cannot be
    // routed through the memory codec (buildDynStructFromStorage would need a storage -> B4 transcode);
    // encode it DIRECTLY from storage with abiEncFromStorage - the SAME recursive encoder `return this.s`
    // uses (echoStorage), proven byte-identical to solc. Produces the bare tuple blob (no return wrapper).
    if (value.kind === 'structValue' && struct.fields.some((f) => isDynStructLeafArrayField(f.type))) {
      const mp = this.fresh();
      out.push(`let ${mp} := mload(0x40)`);
      const size = this.fresh();
      out.push(`let ${size} := ${this.abiEncFromStorage(struct, String(value.baseSlot), 0, mp, out)}`);
      out.push(`mstore(0x40, add(${mp}, ${size}))`);
      return { mp, size };
    }
    const src = this.tupleSrc(value, ctx, out);
    const queue: DynRef[] = [];
    this.collectTupleDyn(struct, src, queue, ctx, out);
    let qi = 0;
    const nextRef = (): DynRef => queue[qi++]!;
    const mp = this.fresh();
    out.push(`let ${mp} := mload(0x40)`);
    const end = this.encodeTupleInto(struct, src, mp, ctx, out, nextRef);
    out.push(`mstore(0x40, ${end})`);
    return { mp, size: `sub(${end}, ${mp})` };
  }

  /** Encode a dynamic struct value as solc's indexed-event TOPIC payload (then keccak'd to
   *  produce the topic). Unlike the ABI encoding, this is the recursively FLATTENED form with
   *  NO offset words and NO length words: a static leaf -> its word(s) inline; bytes/string ->
   *  content padded up to a 32-byte boundary; a dynamic value-array -> its element words; a
   *  nested struct -> its members concatenated. Verified byte-identical to solc (keccak256 of
   *  this blob == the topic). Reuses the same pre-pass + source resolution as the ABI encoder. */
  private encodeTopicBlob(value: Expr, ctx: LowerCtx, out: string[]): { mp: string; size: string } {
    const struct = value.type as JethType & { kind: 'struct' };
    const src = this.tupleSrc(value, ctx, out);
    const queue: DynRef[] = [];
    this.collectTupleDyn(struct, src, queue, ctx, out);
    let qi = 0;
    const nextRef = (): DynRef => queue[qi++]!;
    const mp = this.fresh();
    out.push(`let ${mp} := mload(0x40)`);
    const end = this.topicEncodeStruct(struct, src, mp, ctx, out, nextRef);
    out.push(`mstore(0x40, ${end})`);
    return { mp, size: `sub(${end}, ${mp})` };
  }

  /** Topic-encode a struct's fields sequentially at `tuplePtr` (no head/tail split, no
   *  offsets, no length words). Returns a Yul expr for the cursor just past the payload. */
  private topicEncodeStruct(
    struct: JethType & { kind: 'struct' },
    src: TupleSrc,
    tuplePtr: string,
    ctx: LowerCtx,
    out: string[],
    nextRef: () => DynRef,
  ): string {
    const cursor = this.fresh();
    out.push(`let ${cursor} := ${tuplePtr}`);
    let hw = 0; // running head-word offset within the source tuple (for mem/cd field resolution)
    struct.fields.forEach((f, i) => {
      if (isDynamicType(f.type)) {
        const nc = this.topicEncodeDynField(f, src, i, hw, cursor, ctx, out, nextRef);
        out.push(`${cursor} := ${nc}`);
        hw += 1;
      } else {
        // a static field topic-encodes to exactly its abiHeadWords leaf words inline.
        this.encodeStaticInline(f.type, src, i, hw, cursor, ctx, out);
        out.push(`${cursor} := add(${cursor}, ${abiHeadWords(f.type) * 32})`);
        hw += abiHeadWords(f.type);
      }
    });
    return cursor;
  }

  /** Topic-encode a single DYNAMIC field's payload at `cursor`; returns the new cursor.
   *  bytes/string -> content padded to a word (no length); dynamic value-array -> element
   *  words (no length); nested dynamic struct -> recurse (members concatenated). */
  private topicEncodeDynField(
    f: StructField,
    src: TupleSrc,
    fieldIdx: number,
    headWord: number,
    cursor: string,
    ctx: LowerCtx,
    out: string[],
    nextRef: () => DynRef,
  ): string {
    if (isBytesLike(f.type)) {
      const ref = nextRef();
      const len = this.fresh();
      out.push(`let ${len} := ${this.dynLen(ref)}`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
      const padded = `and(add(${len}, 0x1f), not(0x1f))`;
      const nc = this.fresh();
      out.push(`let ${nc} := add(${cursor}, ${padded})`);
      out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${cursor})) { ${this.panic()}(0x41) }`);
      if (ref.src === 'calldata') {
        out.push(`if gt(add(${ref.dataPtr}, ${len}), calldatasize()) { revert(0, 0) }`);
        out.push(`calldatacopy(${cursor}, ${ref.dataPtr}, ${len})`);
      } else if (ref.src === 'memory') {
        out.push(`mcopy(${cursor}, add(${ref.ptr}, 0x20), ${len})`);
      } else {
        throw new UnsupportedError('topic-encoding a storage bytes/string struct field is not supported yet');
      }
      // zero the partial-word padding tail (one word starting at content end; lies within the
      // freshly-reserved region, so it cannot clobber an already-written earlier field).
      out.push(`if mod(${len}, 0x20) { mstore(add(${cursor}, ${len}), 0) }`);
      return nc;
    }
    if (f.type.kind === 'array' && f.type.length === undefined) {
      if (f.type.element.kind === 'struct')
        throw new UnsupportedError('indexed-topic encoding of a struct-element array field is not supported yet');
      // dynamic value-array: its element words, NO length word (each element is one 32-byte word).
      const ref = nextRef();
      // W6C: an ENUM array field is range-checked on the way out of memory (Panic 0x21) - the
      // image may hold RAW dirty words from a calldata bind copy.
      if (ref.src === 'memory') this.validateEnumMemArray(f.type, ref.ptr, out);
      const len = this.fresh();
      out.push(`let ${len} := ${this.dynLen(ref)}`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
      const byteLen = `mul(${len}, 0x20)`;
      const nc = this.fresh();
      out.push(`let ${nc} := add(${cursor}, ${byteLen})`);
      out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${cursor})) { ${this.panic()}(0x41) }`);
      if (ref.src === 'memory') {
        out.push(`mcopy(${cursor}, add(${ref.ptr}, 0x20), ${byteLen})`);
      } else {
        throw new UnsupportedError('topic-encoding a calldata-array struct field is not supported yet');
      }
      return nc;
    }
    // W5C: a FIXED-outer DYNAMIC-element field (Arr<string,N>/Arr<u256[],N>). The pre-pass queued its
    // self-contained ABI tail (N-word offset table + element tails); walk it packed-padded with the
    // SAME packTopicArray a top-level indexed fixed-outer array uses (base = the table, count = N).
    if (f.type.kind === 'array' && f.type.length !== undefined && isDynLeafFixedArray(f.type)) {
      const ref = nextRef();
      if (ref.src !== 'memory' || !ref.tailBytes)
        throw new UnsupportedError('a fixed-outer dynamic-element struct field must be pre-materialized');
      this.packTopicArray(f.type, ref.ptr, String(f.type.length), cursor, out);
      return cursor;
    }
    if (f.type.kind === 'struct') {
      const nestedSrc = this.nestedTupleSrc(f, src, fieldIdx, headWord, ctx, out);
      return this.topicEncodeStruct(f.type, nestedSrc, cursor, ctx, out, nextRef);
    }
    throw new UnsupportedError(`unsupported dynamic struct field kind '${f.type.kind}'`);
  }

  /** Build solc's indexed-event TOPIC payload for a value/bytes/string-leaf array (string[], bytes[],
   *  u256[][], string[][], Arr<string,N>, Arr<u256[],N>, ...). The preimage is the recursively
   *  FLATTENED "packed-padded" form, with NO length words and NO offset tables: a value leaf is its
   *  32-byte word, a bytes/string leaf is its content right-padded to a 32-byte boundary, nested
   *  arrays are concatenated in order. keccak256 of this blob is the topic (verified byte-identical to
   *  solc across string[], bytes[], u256[][], Arr<string,2>, Arr<u256,3>, multi-word elements).
   *  `tail` is the ABI tail blob from materializeArrayArg: a dynamic outer starts at its [len] header,
   *  a fixed outer at its offset table / element words. The packed blob is built ABOVE the source tail
   *  (materializeArrayArg already advanced the free pointer past it), so reads and writes never alias. */
  private encodeArrayTopicBlob(
    t: JethType & { kind: 'array' },
    tail: string,
    out: string[],
  ): { mp: string; size: string } {
    const mp = this.fresh();
    out.push(`let ${mp} := mload(0x40)`);
    const cursor = this.fresh();
    out.push(`let ${cursor} := ${mp}`);
    const count = t.length === undefined ? `mload(${tail})` : String(t.length);
    const base = t.length === undefined ? `add(${tail}, 0x20)` : tail;
    this.packTopicArray(t, base, count, cursor, out);
    out.push(`mstore(0x40, ${cursor})`);
    return { mp, size: `sub(${cursor}, ${mp})` };
  }

  /** Append array `t`'s packed-padded topic payload (its `count` elements laid out at `base`, with
   *  dynamic-element offsets relative to `base`) to `cursor` (a Yul var mutated in place). Recurses
   *  for nested arrays. See encodeArrayTopicBlob. */
  private packTopicArray(
    t: JethType & { kind: 'array' },
    base: string,
    count: string,
    cursor: string,
    out: string[],
  ): void {
    const elem = t.element;
    if (isStaticType(elem)) {
      // STATIC elements (a value type, a static fixed-array like Arr<u256,2>, a static struct) are laid
      // out INLINE - abiHeadWords each, no offset table, no length. The packed-padded preimage is
      // exactly those inline words, so copy them verbatim in one shot.
      const bytes = abiHeadWords(elem) * 32;
      out.push(`mcopy(${cursor}, ${base}, mul(${count}, ${bytes}))`);
      out.push(`${cursor} := add(${cursor}, mul(${count}, ${bytes}))`);
      return;
    }
    // dynamic elements: the element area at `base` is an offset table; each offset is relative to base.
    const k = this.fresh();
    out.push(`for { let ${k} := 0 } lt(${k}, ${count}) { ${k} := add(${k}, 1) } {`);
    const et = this.fresh();
    out.push(`let ${et} := add(${base}, mload(add(${base}, mul(${k}, 0x20))))`);
    if (isBytesLike(elem)) {
      const len = this.fresh();
      out.push(`let ${len} := mload(${et})`);
      out.push(`mcopy(${cursor}, add(${et}, 0x20), ${len})`);
      out.push(`if mod(${len}, 0x20) { mstore(add(${cursor}, ${len}), 0) }`); // zero the partial-word tail
      out.push(`${cursor} := add(${cursor}, and(add(${len}, 0x1f), not(0x1f)))`);
    } else if (elem.kind === 'array') {
      if (elem.length === undefined) {
        const ic = this.fresh();
        out.push(`let ${ic} := mload(${et})`);
        this.packTopicArray(elem, `add(${et}, 0x20)`, ic, cursor, out);
      } else {
        this.packTopicArray(elem, et, String(elem.length), cursor, out);
      }
    } else if (elem.kind === 'struct') {
      // a DYNAMIC struct element: topic-encode its members packed-padded from its ABI tail at `et`.
      this.packTopicStructFromAbi(elem, et, cursor, out);
    } else {
      throw new UnsupportedError(`indexed-topic array element kind '${elem.kind}' is not supported`);
    }
    out.push(`}`);
  }

  /** Topic-encode a DYNAMIC struct from its ABI-encoded memory layout at `ptr` (the layout
   *  materializeArrayArg produces for a struct array element): value fields are inline at the head;
   *  a bytes/string field is behind a head OFFSET (relative to `ptr`); a static-aggregate field is
   *  inline leaf words. Emits the packed-padded preimage to `cursor` (a Yul var mutated in place):
   *  a value -> its word, a bytes/string -> content right-padded to a 32-byte boundary, a static
   *  aggregate -> its inline leaf words; NO length/offset words. Scoped to value / bytes-string /
   *  static-aggregate fields (isTopicEncodableDynStruct gates deeper dynamic fields out). Verified
   *  byte-identical to solc (keccak256 of the concatenation == the topic). */
  private packTopicStructFromAbi(struct: JethType & { kind: 'struct' }, ptr: string, cursor: string, out: string[]): void {
    let hw = 0; // head-word offset within the struct's ABI head (value=1, static-agg=abiHeadWords, dynamic=1 offset word)
    for (const f of struct.fields) {
      const at = hw === 0 ? ptr : `add(${ptr}, ${hw * 32})`;
      if (isBytesLike(f.type)) {
        const off = this.fresh();
        out.push(`let ${off} := add(${ptr}, mload(${at}))`); // offset relative to the struct start
        const len = this.fresh();
        out.push(`let ${len} := mload(${off})`);
        out.push(`mcopy(${cursor}, add(${off}, 0x20), ${len})`);
        out.push(`if mod(${len}, 0x20) { mstore(add(${cursor}, ${len}), 0) }`); // zero the partial-word tail
        out.push(`${cursor} := add(${cursor}, and(add(${len}, 0x1f), not(0x1f)))`);
        hw += 1;
      } else if (isStaticType(f.type)) {
        // a value (1 word) or a static aggregate (abiHeadWords inline leaf words): the inline words ARE
        // the packed-padded form, copy them verbatim.
        const w = abiHeadWords(f.type);
        out.push(`mcopy(${cursor}, ${at}, ${w * 32})`);
        out.push(`${cursor} := add(${cursor}, ${w * 32})`);
        hw += w;
      } else if (f.type.kind === 'array' && f.type.length === undefined) {
        // Edge C: a DYNAMIC value/bytes/string-element array field (tags: u256[], names: string[]): behind a
        // head OFFSET (relative to the struct start ptr). The data at off is [len][...]; recurse into
        // packTopicArray with the SAME packed-padded element rules a top-level indexed array uses.
        const off = this.fresh();
        out.push(`let ${off} := add(${ptr}, mload(${at}))`);
        const len = this.fresh();
        out.push(`let ${len} := mload(${off})`);
        this.packTopicArray(f.type, `add(${off}, 0x20)`, len, cursor, out);
        hw += 1;
      } else if (f.type.kind === 'array' && f.type.length !== undefined && isDynamicType(f.type)) {
        // W5C: a FIXED-outer DYNAMIC-element array field (Arr<string,N>/Arr<u256[],N>): behind a head
        // OFFSET too, but the tail has NO length word - it IS the N-word per-element offset table
        // (offsets relative to the table start). Walk it with packTopicArray at count = N.
        const off = this.fresh();
        out.push(`let ${off} := add(${ptr}, mload(${at}))`);
        this.packTopicArray(f.type, off, String(f.type.length), cursor, out);
        hw += 1;
      } else if (f.type.kind === 'struct' && isDynamicType(f.type)) {
        // Edge C: a NESTED DYNAMIC struct field (inner: Q): behind a head OFFSET (relative to ptr). Recurse
        // from the nested struct's own start - its members lay out packed-padded by the same rules.
        const off = this.fresh();
        out.push(`let ${off} := add(${ptr}, mload(${at}))`);
        this.packTopicStructFromAbi(f.type, off, cursor, out);
        hw += 1;
      } else {
        throw new UnsupportedError(`indexed-topic struct field kind '${f.type.kind}' is not supported`);
      }
    }
  }

  /** PRE-PASS: walk a tuple in encode order and materialize each bytes/string
   *  field's value into a DynRef (string literals are allocated NOW via toMemory,
   *  before the output blob pointer is captured, so they cannot alias the blob).
   *  Calldata sources need no materialization. Recurses into nested structs in the
   *  exact order encodeTupleInto consumes them. */
  private collectTupleDyn(
    struct: JethType & { kind: 'struct' },
    src: TupleSrc,
    queue: DynRef[],
    ctx: LowerCtx,
    out: string[],
    // W5C: whether a FIXED-outer dynamic-element field may be pre-materialized to a fresh ABI-tail blob
    // (an ALLOCATION) here in the pre-pass. TRUE in the callers that capture their output pointer AFTER
    // this pre-pass (encodeDynStructReturn / encodeDynStructToBlob / encodeTopicBlob). FALSE in the
    // alloc-forbidden contexts whose output pointer is already captured (encodeReturnTuple's
    // memDynStructValue component, abiEncDynStructFromMem at a caller-provided dst): there the 'mem'
    // source queues the BARE image pointer (a single mload, no allocation) and encodeDynFieldInto
    // transcodes it in place at the cursor. The topic encoder REQUIRES the materialized tail, and is
    // only reachable from encodeTopicBlob (materializeFixedTails = true).
    materializeFixedTails = true,
  ): void {
    let hw = 0;
    struct.fields.forEach((f, i) => {
      if (isDynamicType(f.type)) {
        if (isBytesLike(f.type)) {
          const ref = this.dynFieldRef(f, src, i, hw, ctx, out);
          // materialize a memory source now (alloc happens here, below the blob);
          // ALSO materialize a STORAGE source (Pair(k, this.name)): toMemory copies the
          // storage [len][data] to fresh memory via loadStr - the SAME reader abi.encode
          // uses - so encodeDynFieldInto's memory arm then handles it byte-identically and
          // the storage else-throw is never reached. The read runs here in the pre-pass so
          // all field reads precede the output-blob layout (matching solc field ordering).
          // Calldata sources are passed through unchanged (calldatacopy is safe).
          if (ref.src === 'memory' || ref.src === 'storage') {
            const { mp } = this.toMemory(ref, out);
            queue.push({ src: 'memory', ptr: mp });
          } else {
            queue.push(ref);
          }
        } else if (f.type.kind === 'array' && f.type.length === undefined) {
          // a dynamic value-array field: resolve its [len][elems] memory pointer (a memory source is
          // already a pointer; a constructor arg is materialized via aggArgToMemPtr, allocating here
          // in the pre-pass, below the eventual tuple blob).
          queue.push(this.arrayFieldRef(f, src, i, hw, ctx, out));
        } else if (
          f.type.kind === 'array' &&
          f.type.length !== undefined &&
          (isDynLeafFixedArray(f.type) || isDynStructFixedLeafArray(f.type))
        ) {
          // W5C: a FIXED-outer DYNAMIC-element field (Arr<string,N>/Arr<bytes,N>/Arr<u256[],N>), and Lift
          // #4: a FIXED-outer DYNAMIC-STRUCT field (Arr<In,N>). Materialize its SELF-CONTAINED ABI tail
          // (the N-word offset table, offsets relative to the TABLE start, + element tails - a
          // position-independent blob) here in the PRE-PASS (allocs stay below the eventual output blob),
          // carrying tailBytes so both consumers reuse proven codecs verbatim: encodeDynFieldInto's
          // tail-blob copy branch mcopy's it into the tuple; topicEncodeDynField walks it packed-padded.
          // In an alloc-forbidden context (materializeFixedTails = false, output pointer already captured)
          // a 'mem' source instead queues the BARE image pointer (one mload, NO allocation);
          // encodeDynFieldInto then transcodes it at the cursor via abiEncFromMem (whose fixed-of-dynamic
          // branch recurses into abiEncDynStructFromMem for a struct element).
          if (!materializeFixedTails && src.kind === 'mem') {
            const at = hw === 0 ? src.headPtr : `add(${src.headPtr}, ${hw * 32})`;
            const img = this.fresh();
            out.push(`let ${img} := mload(${at})`);
            queue.push({ src: 'memory', ptr: img });
          } else {
            queue.push(this.fixedDynFieldTailRef(f.type, src, i, hw, ctx, out));
          }
        } else if (f.type.kind === 'struct') {
          const nestedSrc = this.nestedTupleSrc(f, src, i, hw, ctx, out);
          this.collectTupleDyn(f.type, nestedSrc, queue, ctx, out, materializeFixedTails);
        } else {
          throw new UnsupportedError(`unsupported dynamic struct field kind '${f.type.kind}'`);
        }
        hw += 1;
      } else {
        hw += abiHeadWords(f.type);
      }
    });
  }

  /** Build the value source for a tuple from a return Expr. */
  private tupleSrc(value: Expr, ctx: LowerCtx, out: string[]): TupleSrc {
    if (value.kind === 'structNew') return { kind: 'new', fields: value.fields, args: value.args };
    if (value.kind === 'cdDynStructValue') {
      const cdStruct = value.type as JethType & { kind: 'struct' };
      // C(2): a calldata dyn-struct with a dynamic VALUE-array field (S{a; tags:u256[]}) has no direct
      // calldata-source array encoder (arrayFieldRef/encodeDynFieldInto throw on a 'cd' source). Materialize
      // it into a fresh pointer-headed memory image (the SAME buildDynStructFromCalldata the local-binding
      // path uses), then encode from a 'mem' source - byte-identical, reusing the proven mem-source path.
      // Admit any array field that is a value-array (Batch C value path) OR a LEAF-array (Edge F:
      // bytes[]/string[]/T[][], a dynamic array whose element is itself dynamic): both are produced by
      // buildDynStructFromCalldata into the SAME pointer-headed image, then encoded from a 'mem' source -
      // byte-identical, reusing the proven mem-source path. A struct with only value/bytes/string fields
      // keeps the direct calldata fast path below (arrFields.length === 0).
      const arrFields = cdStruct.fields.filter((f) => f.type.kind === 'array' && f.type.length === undefined);
      const topLevelArrayAdmitted =
        arrFields.length > 0 &&
        arrFields.every((f) => {
          const el = (f.type as JethType & { kind: 'array' }).element;
          return isStaticValueType(el) || isBytesLike(el) || el.kind === 'array';
        });
      // R3: a NESTED struct field whose own subtree carries an array member (S{a; t:T{u256[]; n}}) also
      // has no direct calldata array encoder - the nested struct field recurses into encodeTupleInto with
      // a 'cd' source, and T's array member then hits arrayFieldRef's `cd` branch (a JETH900 ICE). Route
      // it through the SAME materialize-then-encode path: buildDynStructFromCalldata builds the whole
      // pointer-headed image (its nested-dyn-struct branch recurses and decodes the inner array member),
      // then we encode from a 'mem' source (the proven BIND codec). Detected via structTreeHasArrayMember;
      // topLevelArrayAdmitted already covers the top-level value/leaf/nested-array-field cases.
      const nestedArrayMember = cdStruct.fields.some(
        (f) => f.type.kind === 'struct' && structTreeHasArrayMember(f.type),
      );
      if (topLevelArrayAdmitted || nestedArrayMember) {
        // tupleSrc is the ENCODE-side value source (abi.encode / emit / error / topic; a RETURN of a
        // whole cd param rides echoParam, and `return ds[i]` rides returnCdArrayElem - neither reaches
        // here), so materialize with the RE-ENCODE cap flavor: an oversized inner length EMPTY-reverts
        // (emptyCap = true), byte-identical to solc re-encoding a malformed calldata aggregate.
        const headPtr = this.buildDynStructFromCalldata(cdStruct, value, ctx, out, true);
        return { kind: 'mem', headPtr };
      }
      // V2 fix (fast path, struct with only value/bytes/string fields): a whole NESTED dynamic-struct
      // FIELD read off a calldata parent (o.inner where Inner has no array field) carries a `place` -
      // encode from the FIELD's own tuple-start, not the PARENT param's (which spliced the sibling head).
      if (value.place) {
        return { kind: 'cd', base: this.cdDynStructFieldTupleStart(value.place, cdStruct, ctx, out) };
      }
      const bound = ctx.cdDynStructs.get(value.param);
      if (!bound) throw new UnsupportedError(`dynamic struct param '${value.param}' is not bound`);
      return { kind: 'cd', base: bound.tupleStart };
    }
    if (value.kind === 'memDynStructValue') {
      return { kind: 'mem', headPtr: this.ctxLookup(ctx, value.local) };
    }
    // Residual B3: a whole DYNAMIC-field struct ELEMENT of a memory P[] (xs[i]): lowerArrayGet returns
    // the element's pointer-headed dyn-struct image pointer (an absolute pointer word, deref'd), the
    // same shape a dyn-struct memory local has, so encode it from a 'mem' source.
    if (value.kind === 'arrayGet' && value.type.kind === 'struct' && isDynamicType(value.type)) {
      return { kind: 'mem', headPtr: this.lowerArrayGet(value, ctx, out) };
    }
    if (value.kind === 'ternary') {
      // a DYNAMIC-struct ternary: lower it to a pointer-headed memory image (short-circuit
      // select of buildDynStructLocal per branch), then encode from that mem source.
      return { kind: 'mem', headPtr: this.lowerExpr(value, ctx, out) };
    }
    // W5C (family-wide): a DYNAMIC-struct-returning internal call used directly (`return this.mk(c)` /
    // abi.encode(this.mk(c))): the call yields the pointer-headed image pointer (the same ALIAS
    // buildDynStructLocal's `call` case binds); FREEZE it (the encoder reads it multiple times, and an
    // inline userfn call expression would otherwise be re-invoked per use). Previously threw JETH900.
    if (value.kind === 'call') {
      const p = this.fresh();
      out.push(`let ${p} := ${this.lowerExpr(value, ctx, out)}`);
      return { kind: 'mem', headPtr: p };
    }
    // a whole STORAGE dynamic struct (this.d / this.m[k] / this.recs[i] / placeRead): copy it
    // into a fresh memory image (value fields inline, bytes/string + dyn value-array fields a
    // [len][data] pointer) via the same helper buildDynStructLocal uses, then encode from 'mem'.
    // structSrcSlot throws for genuinely unsupported source kinds, preserving the fail-safe below.
    if (
      value.kind === 'structValue' ||
      value.kind === 'mapStorageValue' ||
      value.kind === 'structArrayElem' ||
      value.kind === 'placeRead'
    ) {
      const struct = value.type as JethType & { kind: 'struct' };
      const headPtr = this.buildDynStructFromStorage(struct, this.structSrcSlot(value, ctx, out), ctx, out);
      return { kind: 'mem', headPtr };
    }
    // abi.encode(xs[i].items[j]) / abi.encode(ds[i]): a whole DYNAMIC struct ELEMENT of a calldata
    // struct array (a direct D[] param, or a D[] FIELD of a calldata dyn-struct array element). Decode
    // the element tuple into a fresh pointer-headed memory image (the SAME buildDynStructFromCalldata the
    // `let d: D = xs[i].items[j]` binding path uses, which resolves the element base via cdArrayElemBase
    // with the unsigned/readability/Panic-0x32 bounds and EMPTY-reverts a malformed inner length - solc's
    // abi.encode calldata->memory decode semantics), then encode from a 'mem' source. cdAggArrayElem is
    // never a dynamic STRUCT (its element is an array), so only cdStructArrayElem reaches here.
    if (value.kind === 'cdStructArrayElem') {
      const struct = value.type as JethType & { kind: 'struct' };
      // ENCODE side (abi.encode(ds[i]) / emit / error / topic; a RETURN rides returnCdArrayElem):
      // materialize with the RE-ENCODE cap flavor - an oversized inner length EMPTY-reverts
      // (emptyCap = true), matching solc's abi.encode calldata->memory decode of a malformed element.
      const headPtr = this.buildDynStructFromCalldata(struct, value, ctx, out, true);
      return { kind: 'mem', headPtr };
    }
    // a whole NESTED DYNAMIC struct FIELD of a dyn-struct memory local (v.t single-level, v.t.u multi-level):
    // the field's head word holds an absolute pointer to the nested image (the OR6 / Edge-A layout), so
    // lowerDynamic yields that image pointer - the same pointer-headed mem source the cases above use.
    if (
      (value.kind === 'memDynField' || value.kind === 'memDynNestedField') &&
      value.type.kind === 'struct' &&
      isDynamicType(value.type)
    ) {
      const ref = this.lowerDynamic(value, ctx, out);
      if (ref.src !== 'memory') throw new UnsupportedError('expected a memory dynamic-struct reference');
      return { kind: 'mem', headPtr: ref.ptr };
    }
    throw new UnsupportedError(`cannot encode dynamic struct from ${value.kind}`);
  }

  /** Recursively encode a struct tuple into memory at `tuplePtr` (the tuple-start
   *  base). Static fields stay inline in the head (declaration order); each dynamic
   *  field gets a head OFFSET word (relative to tuplePtr) and its payload in the
   *  tail (field order). Returns a Yul expr for the memory pointer just past the
   *  tail. Mirrors spec section 3.1 exactly: offsets reset to THIS tuple's start. */
  private encodeTupleInto(
    struct: JethType & { kind: 'struct' },
    src: TupleSrc,
    tuplePtr: string,
    ctx: LowerCtx,
    out: string[],
    nextRef: () => DynRef,
  ): string {
    const headWords = tupleHeadWords(struct);
    // tail cursor starts right after the tuple head.
    const cursor = this.fresh();
    out.push(`let ${cursor} := add(${tuplePtr}, ${headWords * 32})`);
    let hw = 0; // running head-word offset within the tuple
    struct.fields.forEach((f, i) => {
      const headByte = hw * 32;
      const headDst = headByte === 0 ? tuplePtr : `add(${tuplePtr}, ${headByte})`;
      if (isDynamicType(f.type)) {
        // dynamic field: write its offset (cursor - tuplePtr), then its payload.
        out.push(`mstore(${headDst}, sub(${cursor}, ${tuplePtr}))`);
        const newCursor = this.encodeDynFieldInto(f, src, i, hw, cursor, ctx, out, nextRef);
        out.push(`${cursor} := ${newCursor}`);
        hw += 1;
      } else {
        // static field: write its abiHeadWords words inline at headDst.
        this.encodeStaticInline(f.type, src, i, hw, headDst, ctx, out);
        hw += abiHeadWords(f.type);
      }
    });
    return cursor;
  }

  /** Encode a single DYNAMIC field's payload at `cursor`; returns the new cursor.
   *  bytes/string -> [byteLen][right-padded data] (value pulled from the pre-
   *  materialized queue, so no aliasing alloc happens here); a nested dynamic
   *  struct -> its own head/tail tuple (base resets to the nested tuple start). */
  private encodeDynFieldInto(
    f: StructField,
    src: TupleSrc,
    fieldIdx: number,
    headWord: number,
    cursor: string,
    ctx: LowerCtx,
    out: string[],
    nextRef: () => DynRef,
  ): string {
    if (isBytesLike(f.type)) {
      // Write [byteLen][right-padded data] directly at the cursor, copying from the
      // pre-materialized source. calldata -> calldatacopy; memory -> mcopy; then
      // zero the partial-word tail so padding is clean.
      const ref = nextRef();
      const len = this.fresh();
      out.push(`let ${len} := ${this.dynLen(ref)}`);
      // OVERSIZED-LENGTH cap flavor is CONTEXT-split by the source (probe-verified vs solc 0.8.35):
      //   - a CALLDATA source is the abi.encode / emit / error / topic RE-ENCODE of a malformed
      //     calldata bytes/string FIELD -> EMPTY revert (a whole-cd-param RETURN rides echoParam, so a
      //     calldata source here is ALWAYS a re-encode context, never a return-echo).
      //   - a MEMORY source is an in-memory dyn-struct image being encoded -> solc's alloc guard
      //     Panics 0x41 (an oversized memory-resident length; unchanged).
      // Then the new free pointer crossing 2^64-1 (or wrapping) uses the SAME flavor, and a calldata
      // source ALSO validates the payload lies within calldatasize (else EMPTY - a truncated source).
      const bytesCap = ref.src === 'calldata' ? `revert(0, 0)` : `${this.panic()}(0x41)`;
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${bytesCap} }`);
      const padded = `and(add(${len}, 0x1f), not(0x1f))`;
      const nc = this.fresh();
      out.push(`let ${nc} := add(${cursor}, add(0x20, ${padded}))`);
      out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${cursor})) { ${bytesCap} }`);
      if (ref.src === 'calldata') {
        out.push(`if gt(add(${ref.dataPtr}, ${len}), calldatasize()) { revert(0, 0) }`);
        out.push(`mstore(${cursor}, ${len})`);
        out.push(`calldatacopy(add(${cursor}, 0x20), ${ref.dataPtr}, ${len})`);
      } else if (ref.src === 'memory') {
        out.push(`mstore(${cursor}, ${len})`);
        out.push(`mcopy(add(${cursor}, 0x20), add(${ref.ptr}, 0x20), ${len})`);
      } else {
        throw new UnsupportedError('encoding a storage bytes/string struct field is not supported yet');
      }
      out.push(`if mod(${len}, 0x20) { mstore(add(add(${cursor}, 0x20), ${len}), 0) }`);
      return nc;
    }
    if (f.type.kind === 'array' && f.type.length === undefined) {
      const ref = nextRef();
      // Cat C: a NESTED-DYNAMIC-LEAF array field (bytes[]/string[]/T[][]), OR Lift #S: a DYNAMIC-outer
      // struct-ELEMENT array field (Pt[]/Line[]) resolved from a MEMORY dyn-struct image (no tailBytes -
      // arrayFieldRef's mem branch queues the BARE image pointer). The materialized memory image is the
      // B4 / [len]-headed pointer-headed image (NOT a self-contained ABI blob), so transcode it to the
      // canonical ABI tail (relative offsets) at the cursor via abiEncFromMem - the SAME encoder a
      // standalone such array uses (its dynamic-array branch emits [len] + inline static-struct blocks, or
      // an offset table + dynamic-struct tails). A verbatim mcopy would copy absolute element pointers and
      // corrupt the encoding. The `new`-source struct-element path below (which pre-materializes a
      // self-contained ABI tail blob via materializeArrayArg, tailBytes set) still rides the verbatim copy.
      if (ref.src === 'memory' && !ref.tailBytes && (isDynStructLeafArrayField(f.type) || isDynStructElemArrayField(f.type))) {
        const sz = this.fresh();
        out.push(`let ${sz} := ${this.abiEncFromMem(f.type, ref.ptr, cursor, ctx, out)}`);
        const nc = this.fresh();
        out.push(`let ${nc} := add(${cursor}, ${sz})`);
        return nc;
      }
      // A STRUCT-element array field (from a `new`/constructor source): the materialized memory image IS
      // the full ABI tail blob [len][offset-table?][element payloads], a self-contained, position-
      // independent encoding. Copy it verbatim at the cursor (relative offsets stay valid after the
      // move); the new cursor advances by the full image byte size.
      if (ref.src === 'memory' && ref.tailBytes) {
        const nc = this.fresh();
        out.push(`let ${nc} := add(${cursor}, ${ref.tailBytes})`);
        out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${cursor})) { ${this.panic()}(0x41) }`);
        out.push(`mcopy(${cursor}, ${ref.ptr}, ${ref.tailBytes})`);
        return nc;
      }
      // dynamic value-array field tail: [len][word-elements], NO byte-padding (each element is a full
      // 32-byte word). The source is a memory [len][elems] pointer (the materialized array image).
      // W6C: an ENUM array field is range-checked on the way out of memory (Panic 0x21, solc's
      // validator_assert) - the image may hold RAW dirty words from a calldata bind copy.
      if (ref.src === 'memory') this.validateEnumMemArray(f.type, ref.ptr, out);
      const len = this.fresh();
      out.push(`let ${len} := ${this.dynLen(ref)}`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
      const byteLen = `mul(${len}, 0x20)`;
      const nc = this.fresh();
      out.push(`let ${nc} := add(${cursor}, add(0x20, ${byteLen}))`);
      out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${cursor})) { ${this.panic()}(0x41) }`);
      if (ref.src === 'memory') {
        out.push(`mstore(${cursor}, ${len})`);
        out.push(`mcopy(add(${cursor}, 0x20), add(${ref.ptr}, 0x20), ${byteLen})`);
      } else {
        throw new UnsupportedError(
          'encoding a calldata-array struct field in a whole-struct return is not supported yet',
        );
      }
      return nc;
    }
    // W5C: a FIXED-outer DYNAMIC-element field (Arr<string,N>/Arr<bytes,N>/Arr<u256[],N>). The pre-pass
    // queued either its SELF-CONTAINED ABI tail (tailBytes set: N-word offset table relative to the
    // table start + element tails, position-independent - copy it verbatim at the cursor), or, in an
    // alloc-forbidden context, the BARE pointer-headed image (no tailBytes) - transcode it at the
    // cursor via abiEncFromMem's fixed-outer branch (identical bytes; writes only at/past the cursor).
    if (f.type.kind === 'array' && f.type.length !== undefined && (isDynLeafFixedArray(f.type) || isDynStructFixedLeafArray(f.type))) {
      const ref = nextRef();
      if (ref.src !== 'memory')
        throw new UnsupportedError('a fixed-outer dynamic-element struct field must be memory-resolved');
      if (!ref.tailBytes) {
        const sz = this.fresh();
        out.push(`let ${sz} := ${this.abiEncFromMem(f.type, ref.ptr, cursor, ctx, out)}`);
        const nc = this.fresh();
        out.push(`let ${nc} := add(${cursor}, ${sz})`);
        return nc;
      }
      const nc = this.fresh();
      out.push(`let ${nc} := add(${cursor}, ${ref.tailBytes})`);
      out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${cursor})) { ${this.panic()}(0x41) }`);
      out.push(`mcopy(${cursor}, ${ref.ptr}, ${ref.tailBytes})`);
      return nc;
    }
    if (f.type.kind === 'struct') {
      // nested dynamic struct: encode it as its own tuple starting at cursor.
      const nestedSrc = this.nestedTupleSrc(f, src, fieldIdx, headWord, ctx, out);
      return this.encodeTupleInto(f.type, nestedSrc, cursor, ctx, out, nextRef);
    }
    throw new UnsupportedError(`unsupported dynamic struct field kind '${f.type.kind}'`);
  }

  /** Resolve a bytes/string field's value to a DynRef from the tuple source. This is
   *  the WHOLE-struct ECHO path (return d), so the calldata case uses the ECHO-DECODE
   *  helper (unsigned offset cap, no length cap / payload-fits); the alloc Panic(0x41)
   *  and the payload-within-calldatasize check land in encodeDynFieldInto's copy. */
  private dynFieldRef(
    f: StructField,
    src: TupleSrc,
    fieldIdx: number,
    headWord: number,
    ctx: LowerCtx,
    out: string[],
  ): DynRef {
    if (src.kind === 'new') return this.lowerDynamic(src.args[fieldIdx]!, ctx, out);
    if (src.kind === 'mem') {
      // the head word holds the [len][data] memory pointer of the bytes/string field.
      const at = headWord === 0 ? src.headPtr : `add(${src.headPtr}, ${headWord * 32})`;
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(${at})`);
      return { src: 'memory', ptr };
    }
    // calldata echo: read the field's offset word at base + headWord*32, resolve.
    const offPtr = headWord === 0 ? src.base : `add(${src.base}, ${headWord * 32})`;
    const dataPtr = this.fresh();
    const len = this.fresh();
    out.push(`let ${dataPtr}, ${len} := ${this.calldataDynAtEcho()}(${src.base}, ${offPtr})`);
    return { src: 'calldata', dataPtr, len };
  }

  /** Resolve a dynamic value-array field of a dynamic-field struct to a memory [len][elems] pointer
   *  (for whole-struct `return d` encoding). A memory source's head word already holds the pointer; a
   *  constructor arg is materialized via aggArgToMemPtr. A calldata source stays gated (the analyzer
   *  rejects returning a calldata struct param that carries an array field). */
  private arrayFieldRef(
    f: StructField,
    src: TupleSrc,
    fieldIdx: number,
    headWord: number,
    ctx: LowerCtx,
    out: string[],
  ): DynRef {
    // A STRUCT-element dynamic array field (Q[]): materialize the WHOLE ABI tail blob [len][...] (an
    // offset table + element payloads for dynamic-struct elements; contiguous abiHeadWords element
    // words for static ones), and carry its full byte size so the tail copy is exact (the
    // value-element path below copies just [len][len*32] and so cannot express a struct stride/table).
    const elemIsStruct = f.type.kind === 'array' && f.type.element.kind === 'struct';
    if (src.kind === 'new') {
      if (elemIsStruct) {
        const { mp, size } = this.materializeArrayArg(src.args[fieldIdx]!, ctx, out);
        return { src: 'memory', ptr: mp, tailBytes: size };
      }
      return { src: 'memory', ptr: this.aggArgToMemPtr(src.args[fieldIdx]!, ctx, out) };
    }
    if (src.kind === 'mem') {
      // Lift #S: a DYNAMIC-outer struct-ELEMENT array field (Pt[]/Line[]) of a memory dyn-struct: the head
      // word holds the array image pointer ([len][per-element block]). Queue the BARE image pointer (a
      // single mload, NO allocation - safe in an alloc-forbidden pre-pass context too); encodeDynFieldInto
      // transcodes it IN PLACE at the cursor via abiEncFromMem (its dynamic-array branch emits [len] +
      // inline static-struct blocks or an offset table + dynamic-struct tails), the SAME encoder a
      // standalone Pt[]/Line[] uses - byte-identical, NO tailBytes (an in-place transcode, not a verbatim
      // tail copy). A verbatim mcopy would copy absolute element-image pointers and corrupt the encoding.
      const at = headWord === 0 ? src.headPtr : `add(${src.headPtr}, ${headWord * 32})`;
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(${at})`);
      return { src: 'memory', ptr };
    }
    throw new UnsupportedError('returning a calldata struct param with an array field is not supported yet');
  }

  /** W5C: resolve a FIXED-outer DYNAMIC-element array field (Arr<string,N>/Arr<bytes,N>/Arr<u256[],N>)
   *  of a dyn-struct tuple to its SELF-CONTAINED ABI tail {ptr, tailBytes}: the N-word offset table
   *  (offsets relative to the TABLE start) + element tails, a position-independent blob. Runs in the
   *  collectTupleDyn PRE-PASS (all allocation happens below the eventual output blob). Consumers:
   *  encodeDynFieldInto mcopy's it verbatim behind the field's head offset; topicEncodeDynField walks it
   *  packed-padded via packTopicArray (count = N).
   *   - 'new' (an inline constructor arg): materialize the pointer-headed image (aggArgToMemPtr handles a
   *     literal via buildNestedMemArrayLit, a memory local/param alias, a storage/calldata copy), then
   *     transcode via abiEncFromMem's fixed-outer branch - the materializeFixedDynLeafTail pattern.
   *   - 'mem' (a memory dyn-struct image): the field head word holds the image pointer; transcode it.
   *   - 'cd' (a calldata dyn-struct tuple): the field head word is an offset to the calldata tail;
   *     re-encode it via abiEncFromCd (validating, Panic 0x41 alloc cap - solc's calldata deep-copy). */
  private fixedDynFieldTailRef(
    ft: JethType & { kind: 'array' },
    src: TupleSrc,
    fieldIdx: number,
    headWord: number,
    ctx: LowerCtx,
    out: string[],
  ): DynRef {
    if (src.kind === 'new' || src.kind === 'mem') {
      let img: string;
      if (src.kind === 'new') {
        img = this.aggArgToMemPtr(src.args[fieldIdx]!, ctx, out);
      } else {
        const at = headWord === 0 ? src.headPtr : `add(${src.headPtr}, ${headWord * 32})`;
        img = this.fresh();
        out.push(`let ${img} := mload(${at})`);
      }
      const dst = this.fresh();
      out.push(`let ${dst} := mload(0x40)`);
      const sz = this.fresh();
      out.push(`let ${sz} := ${this.abiEncFromMem(ft, img, dst, ctx, out)}`);
      out.push(`mstore(0x40, add(${dst}, ${sz}))`);
      return { src: 'memory', ptr: dst, tailBytes: sz };
    }
    // calldata: field head word = offset (relative to the tuple start) to the N-word offset table.
    // A 'cd' source only reaches collectTupleDyn from the abi.encode / event-data / indexed-topic /
    // custom-error materialization (a whole-cd RETURN rides echoParam / echoCdDynField instead), so the
    // oversized-length cap is the DECODE/re-encode flavor: EMPTY revert (capEmptyRevert = true),
    // probe-verified vs solc 0.8.35 (abi.encode/emit of a cd struct with a huge inner string length
    // reverts EMPTY; only the return-echo path Panics 0x41).
    const offPtr = headWord === 0 ? src.base : `add(${src.base}, ${headWord * 32})`;
    const so = this.fresh();
    out.push(`let ${so} := calldataload(${offPtr})`);
    out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
    const se = this.fresh();
    out.push(`let ${se} := add(${src.base}, ${so})`);
    out.push(`if gt(add(${se}, ${ft.length! * 32}), calldatasize()) { revert(0, 0) }`);
    const dst = this.fresh();
    out.push(`let ${dst} := mload(0x40)`);
    const sz = this.fresh();
    out.push(`let ${sz} := ${this.abiEncFromCd(ft, se, dst, true, out, true)}`);
    out.push(`mstore(0x40, add(${dst}, ${sz}))`);
    return { src: 'memory', ptr: dst, tailBytes: sz };
  }

  /** Build the value source for a nested (sub)struct field. */
  private nestedTupleSrc(
    f: StructField,
    src: TupleSrc,
    fieldIdx: number,
    headWord: number,
    ctx: LowerCtx,
    out: string[],
  ): TupleSrc {
    const nested = f.type as JethType & { kind: 'struct' };
    if (src.kind === 'new') {
      const arg = src.args[fieldIdx]!;
      if (arg.kind !== 'structNew') {
        // W6A: a nested DYNAMIC struct field captured from a NON-INLINE source (a memory dyn-struct
        // local / param / nested field / element / call - the analyzer now passes references
        // through). Materialize the source's pointer-headed image (buildDynStructLocal ALIASES a
        // memory source, copies storage/calldata) and encode from the 'mem' branch - the encoder
        // reads the same words solc's reference would.
        const headPtr = this.buildDynStructLocal(nested, arg, ctx, out);
        return { kind: 'mem', headPtr };
      }
      return { kind: 'new', fields: arg.fields, args: arg.args };
    }
    if (src.kind === 'mem') {
      // a nested DYNAMIC struct field of a memory dyn-struct image: the head word holds a POINTER to the
      // nested struct's own pointer-headed image (stored by allocDynStructToMem); follow it. (A nested
      // STATIC struct is encoded inline via encodeStaticInline and never reaches nestedTupleSrc.)
      const at = headWord === 0 ? src.headPtr : `add(${src.headPtr}, ${headWord * 32})`;
      const nb = this.fresh();
      out.push(`let ${nb} := mload(${at})`);
      return { kind: 'mem', headPtr: nb };
    }
    // calldata echo. If the nested struct is dynamic, its head slot is an offset
    // word (base resets to base + offset); if static, it is inline at base+head.
    const fieldOff = headWord === 0 ? src.base : `add(${src.base}, ${headWord * 32})`;
    if (isDynamicType(nested)) {
      const nb = this.fresh();
      out.push(`let ${nb} := ${this.calldataTupleAt()}(${src.base}, ${fieldOff}, ${tupleHeadWords(nested) * 32})`);
      return { kind: 'cd', base: nb };
    }
    return { kind: 'cd', base: fieldOff };
  }

  /** Write a STATIC field's `abiHeadWords` words inline at memory `dstPtr` (one
   *  unpacked ABI word per leaf). new source: lower each leaf value (recursing into
   *  nested static structs); cd source: copy + validate each leaf word from the
   *  calldata tuple at base + headWord*32. */
  private encodeStaticInline(
    type: JethType,
    src: TupleSrc,
    fieldIdx: number,
    headWord: number,
    dstPtr: string,
    ctx: LowerCtx,
    out: string[],
  ): void {
    if (src.kind === 'new') {
      // a static value field, or a nested static struct constructed inline.
      const arg = src.args[fieldIdx]!;
      if (type.kind === 'struct' || (type.kind === 'array' && type.length !== undefined)) {
        // flatten via abiLeaves; the structNew args provide the leaf values.
        const leaves = this.staticNewLeaves(type, arg, ctx, out);
        leaves.forEach((w, k) => out.push(`mstore(${k === 0 ? dstPtr : `add(${dstPtr}, ${k * 32})`}, ${w})`));
        return;
      }
      const w = this.lowerExpr(arg, ctx, out);
      out.push(`mstore(${dstPtr}, ${w})`);
      return;
    }
    if (src.kind === 'mem') {
      // a field of a memory dynamic struct's image. A value field is one inline word; a nested STATIC
      // aggregate (struct / fixed-array) occupies abiHeadWords(type) consecutive head words in the
      // image (the image is already ABI-flattened), so copy ALL of them - reading just the first word
      // would drop the rest (corrupting the encoded tuple / event topic preimage / event data).
      const n = abiHeadWords(type);
      const at = headWord === 0 ? src.headPtr : `add(${src.headPtr}, ${headWord * 32})`;
      if (n === 1) {
        const w = this.fresh();
        out.push(`let ${w} := mload(${at})`);
        out.push(`mstore(${dstPtr}, ${w})`);
      } else {
        out.push(`mcopy(${dstPtr}, ${at}, ${n * 32})`);
      }
      return;
    }
    // calldata echo: copy + validate each leaf word.
    const srcBaseOff = headWord === 0 ? src.base : `add(${src.base}, ${headWord * 32})`;
    for (const leaf of abiLeaves(type)) {
      const disp = leaf.wordOffset * 32;
      const at = disp === 0 ? srcBaseOff : `add(${srcBaseOff}, ${disp})`;
      const w = this.fresh();
      out.push(`let ${w} := calldataload(${at})`);
      const guard = this.validateInput(leaf.type, w);
      if (guard) out.push(guard);
      out.push(`mstore(${disp === 0 ? dstPtr : `add(${dstPtr}, ${disp})`}, ${w})`);
    }
  }

  /** Collect the unpacked ABI leaf words of a STATIC aggregate built by a structNew
   *  (recursing into nested static struct args). The order matches abiLeaves(type). */
  private staticNewLeaves(type: JethType, arg: Expr, ctx: LowerCtx, out: string[]): string[] {
    if (type.kind === 'struct') {
      if (arg.kind !== 'structNew') throw new UnsupportedError('static nested struct must be constructed inline');
      const words: string[] = [];
      type.fields.forEach((f, i) => words.push(...this.staticNewLeaves(f.type, arg.args[i]!, ctx, out)));
      return words;
    }
    if (type.kind === 'array' && type.length !== undefined) {
      // a static fixed-array field, built from an array literal: flatten each element's leaf words
      // (recursing into nested fixed-arrays / structs), one ABI word per value leaf.
      if (arg.kind !== 'arrayLit')
        throw new UnsupportedError('a static fixed-array struct field must be constructed from an array literal');
      const words: string[] = [];
      arg.elements.forEach((el) => words.push(...this.staticNewLeaves(type.element, el, ctx, out)));
      return words;
    }
    return [this.lowerExpr(arg, ctx, out)];
  }

  // ---- nested storage access (Phase 4c-3) ----------------------------------

  /** Fold an AccessPath into a (slot expr, byte offset). Constant steps fold to a
   *  constant slot; mapping keys and dynamic indices produce runtime slot temps.
   *  Index steps are over whole-slot elements (stride in slots), offset stays 0;
   *  field steps add the field slot and set the packing offset. */
  private lowerPlace(
    path: AccessPath,
    ctx: LowerCtx,
    out: string[],
  ): { slot: string; offset: number; byteShift?: string } {
    let constSlot: bigint | null = path.baseSlot;
    let slot = String(path.baseSlot);
    let offset = 0;
    let byteShift: string | undefined; // a RUNTIME byte offset within the slot (packed elem)
    // @public auto-getters revert EMPTY on an out-of-bounds index (solc parity); ordinary access Panics.
    const oob = path.oobEmpty ? 'revert(0, 0)' : `${this.panic()}(0x32)`;
    for (const step of path.steps) {
      if (step.kind === 'field') {
        if (constSlot !== null) {
          constSlot += BigInt(step.fieldSlot);
          slot = String(constSlot);
        } else if (step.fieldSlot !== 0) {
          slot = `add(${slot}, ${step.fieldSlot})`;
        }
        offset = step.fieldOffset;
      } else if (step.kind === 'index') {
        if (step.index.kind === 'literalInt') {
          const add = step.index.value * BigInt(step.strideSlots);
          if (constSlot !== null) {
            constSlot += add;
            slot = String(constSlot);
          } else if (add !== 0n) {
            slot = `add(${slot}, ${add})`;
          }
        } else {
          const it = this.fresh();
          out.push(`let ${it} := ${this.lowerExpr(step.index, ctx, out)}`);
          out.push(`if iszero(lt(${it}, ${step.length})) { ${oob} }`);
          const delta = step.strideSlots === 1 ? it : `mul(${it}, ${step.strideSlots})`;
          slot = `add(${constSlot !== null ? constSlot : slot}, ${delta})`;
          constSlot = null;
        }
        offset = 0;
      } else if (step.kind === 'packedIndex') {
        // packed fixed-array element (perSlot per slot): slot = base + i/perSlot, with a
        // byte offset (i%perSlot)*size within that slot (constant if i is literal).
        if (step.index.kind === 'literalInt') {
          const k = step.index.value;
          const slotAdd = k / BigInt(step.perSlot); // bigint division truncates toward zero (k >= 0)
          if (constSlot !== null) {
            constSlot += slotAdd;
            slot = String(constSlot);
          } else if (slotAdd !== 0n) {
            slot = `add(${slot}, ${slotAdd})`;
          }
          offset = Number(k % BigInt(step.perSlot)) * step.size;
          byteShift = undefined;
        } else {
          const it = this.fresh();
          out.push(`let ${it} := ${this.lowerExpr(step.index, ctx, out)}`);
          out.push(`if iszero(lt(${it}, ${step.length})) { ${oob} }`);
          const base = constSlot !== null ? String(constSlot) : slot;
          slot = `add(${base}, div(${it}, ${step.perSlot}))`;
          byteShift = `mul(mod(${it}, ${step.perSlot}), ${step.size})`;
          constSlot = null;
          offset = 0;
        }
      } else if (step.kind === 'dynIndex') {
        // dynamic T[] element: bound vs sload(lenSlot); data at keccak(lenSlot).
        const lenSlot = constSlot !== null ? String(constSlot) : slot;
        const it = this.fresh();
        out.push(`let ${it} := ${this.lowerExpr(step.index, ctx, out)}`);
        out.push(`if iszero(lt(${it}, sload(${lenSlot}))) { ${oob} }`);
        const dataBase = this.fresh();
        out.push(`let ${dataBase} := ${this.arrayDataSlotHelper()}(${lenSlot})`);
        const delta = step.strideSlots === 1 ? it : `mul(${it}, ${step.strideSlots})`;
        slot = `add(${dataBase}, ${delta})`;
        constSlot = null;
        offset = 0;
      } else if (step.kind === 'packedDynIndex') {
        // packed element of a dynamic T[]: bound vs sload(lenSlot); data at keccak(lenSlot);
        // slot = dataBase + i/perSlot, byte offset (i%perSlot)*size within that slot.
        const lenSlot = constSlot !== null ? String(constSlot) : slot;
        const it = this.fresh();
        out.push(`let ${it} := ${this.lowerExpr(step.index, ctx, out)}`);
        out.push(`if iszero(lt(${it}, sload(${lenSlot}))) { ${oob} }`);
        const dataBase = this.fresh();
        out.push(`let ${dataBase} := ${this.arrayDataSlotHelper()}(${lenSlot})`);
        if (step.index.kind === 'literalInt') {
          const k = step.index.value;
          const slotAdd = k / BigInt(step.perSlot); // bigint division truncates toward zero (k >= 0)
          slot = slotAdd === 0n ? dataBase : `add(${dataBase}, ${slotAdd})`;
          offset = Number(k % BigInt(step.perSlot)) * step.size;
          byteShift = undefined;
        } else {
          slot = `add(${dataBase}, div(${it}, ${step.perSlot}))`;
          byteShift = `mul(mod(${it}, ${step.perSlot}), ${step.size})`;
          offset = 0;
        }
        constSlot = null;
      } else {
        // mapping key: slot = keccak256(key . currentSlot). A bytes/string key hashes its
        // RAW content bytes (unpadded) concatenated with the slot word (the same derivation
        // as mappingSlot()); a value-type key hashes the 32-byte key word + slot word.
        const cur = constSlot !== null ? String(constSlot) : slot;
        if (isBytesLike(step.key.type)) {
          const { mp, len } = this.toMemory(this.lowerDynamic(step.key, ctx, out), out);
          const ptr = this.fresh();
          out.push(`let ${ptr} := mload(0x40)`);
          out.push(`mcopy(${ptr}, add(${mp}, 0x20), ${len})`);
          out.push(`mstore(add(${ptr}, ${len}), ${cur})`);
          const tmp = this.fresh();
          out.push(`let ${tmp} := keccak256(${ptr}, add(${len}, 0x20))`);
          slot = tmp;
        } else {
          const k = this.lowerExpr(step.key, ctx, out);
          const tmp = this.fresh();
          out.push(`mstore(0x00, ${k})`);
          out.push(`mstore(0x20, ${cur})`);
          out.push(`let ${tmp} := keccak256(0x00, 0x40)`);
          slot = tmp;
        }
        constSlot = null;
        offset = 0;
      }
    }
    return { slot, offset, byteShift };
  }

  /** Fold a CalldataPlace (struct/fixed-array param navigation) into a calldata
   *  byte-offset expression. The ABI head is UNPACKED: a field step adds a const
   *  word offset; an index step bounds-checks (Panic 0x32) then adds idx*stride.
   *  A constant index needs no runtime check (the analyzer rejected OOB literals,
   *  matching solc's compile-time "out of bounds array access"). */
  private lowerCdPlace(place: CalldataPlace, ctx: LowerCtx, out: string[]): string {
    const agg = ctx.cdAggregates.get(place.param);
    if (!agg) throw new UnsupportedError(`calldata aggregate param '${place.param}' is not bound`);
    let constOff = agg.baseOffset;
    let off: string | null = null; // set once a dynamic index appears
    for (const step of place.steps) {
      if (step.kind === 'field') {
        const add = 32 * step.headWords;
        if (off === null) constOff += add;
        else if (add !== 0) off = `add(${off}, ${add})`;
      } else {
        const stride = 32 * step.strideWords;
        if (step.index.kind === 'literalInt') {
          const add = Number(step.index.value) * stride;
          if (off === null) constOff += add;
          else if (add !== 0) off = `add(${off}, ${add})`;
        } else {
          const it = this.fresh();
          out.push(`let ${it} := ${this.lowerExpr(step.index, ctx, out)}`);
          out.push(`if iszero(lt(${it}, ${step.length})) { ${this.panic()}(0x32) }`);
          off = `add(${off === null ? constOff : off}, mul(${it}, ${stride}))`;
        }
      }
    }
    return off === null ? String(constOff) : off;
  }

  // ---- dynamic structs (Phase 4e-6) ----------------------------------------

  /** Walk the all-but-last steps of a dynamic-struct place, returning the calldata
   *  byte pointer of the tuple that CONTAINS the final field. The base resets at
   *  each dynamic-struct boundary: a static nested-struct field is inline (new base
   *  = field word addr); a dynamic nested-struct field stores an offset word (new
   *  base = current base + that offset, spec section 3.2). A bad nested offset /
   *  unreadable tuple head -> EMPTY revert. Returns a Yul expr for the base. */
  private lowerCdDynBase(place: CdDynPlace, ctx: LowerCtx, out: string[]): string {
    let base: string;
    if (place.arrayRoot) {
      // base tuple = ds[i] of a dynamic-struct array: resolve via the offset table.
      const ref = this.lowerArrayRef(place.arrayRoot.arr, ctx, out);
      if (ref.src !== 'calldata') throw new UnsupportedError('dynamic-struct-array element requires a calldata array');
      const i = this.fresh();
      out.push(`let ${i} := ${this.lowerExpr(place.arrayRoot.index, ctx, out)}`);
      out.push(`if iszero(lt(${i}, ${ref.length})) { ${this.panic()}(0x32) }`);
      const eo = this.fresh();
      out.push(`let ${eo} := calldataload(add(${ref.offset}, mul(${i}, 0x20)))`);
      // lazy-access element offset: solc signed slt + modular wrap (base = table start).
      // The element is a dynamic-struct TUPLE: its WHOLE head (headWords*32 bytes), not
      // just the first field word, must be in range (else solc EMPTY-reverts).
      const elemHead = tupleHeadWords(place.arrayRoot.arr.elem as JethType & { kind: 'struct' }) * 32;
      out.push(`if iszero(slt(${eo}, sub(sub(calldatasize(), ${ref.offset}), ${elemHead - 1}))) { revert(0, 0) }`);
      const ts = this.fresh();
      out.push(`let ${ts} := add(${ref.offset}, ${eo})`);
      base = ts;
    } else {
      const bound = ctx.cdDynStructs.get(place.param);
      if (!bound) throw new UnsupportedError(`dynamic struct param '${place.param}' is not bound`);
      base = bound.tupleStart;
    }
    // process every step except the last (the caller resolves the final field).
    for (let k = 0; k < place.steps.length - 1; k++) {
      const step = place.steps[k]!;
      const fieldOff = step.headWords === 0 ? base : `add(${base}, ${step.headWords * 32})`;
      if (step.crossDynamic) {
        // a nested DYNAMIC struct: read its offset word; new base = base + offset.
        const fst = step.fieldType as JethType & { kind: 'struct' };
        const headSize = tupleHeadWords(fst) * 32;
        const nb = this.fresh();
        out.push(`let ${nb} := ${this.calldataTupleAt()}(${base}, ${fieldOff}, ${headSize})`);
        base = nb;
      } else {
        // a nested STATIC struct: inline at fieldOff; new base = fieldOff.
        const nb = this.fresh();
        out.push(`let ${nb} := ${fieldOff}`);
        base = nb;
      }
    }
    return base;
  }

  /** Resolve a static-value leaf of a dynamic-struct place to its calldata byte
   *  offset (the leaf word address). The leaf word is validated on read by the
   *  caller (dirty bits -> EMPTY revert), matching solc's lazy field validation. */
  private lowerCdDynLeafOff(place: CdDynPlace, ctx: LowerCtx, out: string[]): string {
    const base = this.lowerCdDynBase(place, ctx, out);
    const last = place.steps[place.steps.length - 1]!;
    return last.headWords === 0 ? base : `add(${base}, ${last.headWords * 32})`;
  }

  // ---- dynamic arrays (Phase 4b) -------------------------------------------

  private lowerArrayRef(arr: ArrayExpr, ctx: LowerCtx, out: string[]): ArrayRef {
    if (arr.base.kind === 'stateArray') {
      return { src: 'storage', lenSlot: String(arr.base.slot), elem: arr.elem };
    }
    if (arr.base.kind === 'fixedArray') {
      return { src: 'fixed', baseSlot: arr.base.baseSlot, length: arr.base.length, elem: arr.elem };
    }
    if (arr.base.kind === 'mapArray') {
      // a mapping-valued dynamic array: length lives at the runtime mapping slot.
      const lenSlot = this.mappingSlot(arr.base.baseSlot, arr.base.keys, ctx, out);
      return { src: 'storage', lenSlot, elem: arr.elem };
    }
    if (arr.base.kind === 'placeArray') {
      // a storage inner dynamic array (nested-array element / dyn-array struct field):
      // its length slot is the AccessPath slot; data at keccak(that slot).
      const p = this.lowerPlace(arr.base.path, ctx, out);
      return { src: 'storage', lenSlot: p.slot, elem: arr.elem };
    }
    if (arr.base.kind === 'cdDynArrayField') {
      // a dynamic value-array field of a calldata dynamic-struct param (s.xs): the field's head slot
      // holds an offset (relative to the containing tuple start) to the array's [len][elems]. Decode
      // with the ARRAY helper (unsigned offset bound + FULL len*stride payload-fit), NOT the
      // bytes/string helper (which checks len+0x20 bytes and a signed offset) - matching solc's
      // array-member decode. stride = 0x20 (value elements are one ABI word each).
      const place = arr.base.place;
      const base = this.lowerCdDynBase(place, ctx, out);
      const last = place.steps[place.steps.length - 1]!;
      const offPtr = last.headWords === 0 ? base : `add(${base}, ${last.headWords * 32})`;
      const dataPtr = this.fresh();
      const len = this.fresh();
      // stride = the per-element width of the array's HEADER region after [len]: a STATIC element
      // (a value u256, or a static struct in D[]) is contiguous, abiHeadWords(elem)*32 bytes each;
      // a DYNAMIC element (a dynamic struct in D[], bytes[]/string[], T[][]) is offset-located, ONE
      // 0x20 offset word each. calldataArrayAt validates `dataOff + len*stride <= calldatasize()`, so
      // the stride MUST match the actual header layout (a dynamic struct's offset table is 0x20 per
      // element, NOT abiHeadWords*32 - which would over-require payload and EMPTY-revert valid input).
      // `dataPtr` is then the offset-table base for a dynamic element (consumed by cdArrayElemBase's
      // dynamic branch) or the contiguous element-0 base for a static element.
      const stride = isDynamicType(arr.elem) ? 32 : abiHeadWords(arr.elem) * 32;
      out.push(`let ${dataPtr}, ${len} := ${this.calldataArrayAt()}(${base}, ${offPtr}, ${stride})`);
      return { src: 'calldata', offset: dataPtr, length: len, elem: arr.elem };
    }
    if (arr.base.kind === 'cdDynFieldNested') {
      // An inner array reached by indexing a NESTED-dynamic-array field of a calldata dyn-struct
      // param (s.grid[i] of u256[][], s.deep[i][j] of u256[][][]). First decode the FIELD's tail to
      // (tableStart, outerLen): the field's head slot holds an offset to the array header, decoded with
      // the ARRAY helper at stride 0x20 (the outer element is a dynamic array = one offset word each), so
      // tableStart = the word after the length word = the per-element offset base. Then descend one inner-
      // offset-table level per index, bounds-checking each dim (Panic 0x32), exactly like cdNestedElem.
      const place = arr.base.place;
      const cbase = this.lowerCdDynBase(place, ctx, out);
      const last = place.steps[place.steps.length - 1]!;
      const offPtr = last.headWords === 0 ? cbase : `add(${cbase}, ${last.headWords * 32})`;
      const tableStart = this.fresh();
      const outerLen = this.fresh();
      out.push(`let ${tableStart}, ${outerLen} := ${this.calldataArrayAt()}(${cbase}, ${offPtr}, 0x20)`);
      const fieldArr = last.fieldType as JethType & { kind: 'array' };
      let base = tableStart;
      let count: string = outerLen;
      let elemT: JethType = fieldArr.element;
      arr.base.indices.forEach((idxExpr) => {
        const i = this.fresh();
        out.push(`let ${i} := ${this.lowerExpr(idxExpr, ctx, out)}`);
        out.push(`if iszero(lt(${i}, ${count})) { ${this.panic()}(0x32) }`);
        if (elemT.kind === 'array' && elemT.length === undefined) {
          const stride = isDynamicType(elemT.element) ? 32 : abiHeadWords(elemT.element) * 32;
          const nb = this.fresh();
          const nl = this.fresh();
          out.push(`let ${nb}, ${nl} := ${this.calldataInnerArray()}(${base}, ${i}, ${stride})`);
          base = nb;
          count = nl;
        } else if (elemT.kind === 'array' && elemT.length !== undefined) {
          const nb = this.fresh();
          out.push(`let ${nb} := ${this.calldataNestedOff()}(${base}, ${i})`);
          base = nb;
          count = String(elemT.length);
        } else {
          throw new UnsupportedError(`cannot index calldata dyn-struct nested field element of kind '${elemT.kind}'`);
        }
        elemT = (elemT as JethType & { kind: 'array' }).element;
      });
      return { src: 'calldata', offset: base, length: count, elem: arr.elem };
    }
    if (arr.base.kind === 'cdDynFixedField') {
      // an inline fixed-array-of-value field (s.xs where xs: Arr<T,N>): the N element words sit inline
      // in the tuple head at the field's byte offset. No tail decode: element i is the word at
      // fieldOff + i*32. length is the compile-time constant N. arrayGet bounds-checks (Panic 0x32)
      // and validates dirty calldata bits on read, matching solc's inline static-array element read.
      const place = arr.base.place;
      const base = this.lowerCdDynBase(place, ctx, out);
      const last = place.steps[place.steps.length - 1]!;
      const offset = last.headWords === 0 ? base : `add(${base}, ${last.headWords * 32})`;
      return { src: 'calldata', offset, length: String(arr.base.length), elem: arr.elem };
    }
    if (arr.base.kind === 'cdDynFixedDynField') {
      // W5C: a FIXED-outer DYNAMIC-element field (s.xs where xs: Arr<string,N>/Arr<bytes,N>): the field
      // is dynamic, so its head slot holds an offset (relative to the containing tuple start) to the
      // tail = the N-word per-element offset table (NO length word). LAZY member access mirrors solc's
      // access_calldata_tail_t_array$_..._$N EXACTLY (probe-verified vs 0.8.35): a SIGNED bound
      // `slt(rel, calldatasize() - base - (N*32 - 1))` (so a huge "negative" offset like 2^256-1
      // PASSES here and faults, if at all, at the ELEMENT access - byte-identical), then
      // tableStart = base + rel with NO unsigned 2^64 cap (that cap belongs to the DECODE paths only).
      const place = arr.base.place;
      const base = this.lowerCdDynBase(place, ctx, out);
      const last = place.steps[place.steps.length - 1]!;
      const offPtr = last.headWords === 0 ? base : `add(${base}, ${last.headWords * 32})`;
      const so = this.fresh();
      out.push(`let ${so} := calldataload(${offPtr})`);
      out.push(`if iszero(slt(${so}, sub(sub(calldatasize(), ${base}), ${arr.base.length * 32 - 1}))) { revert(0, 0) }`);
      const tbl = this.fresh();
      out.push(`let ${tbl} := add(${base}, ${so})`);
      return { src: 'calldata', offset: tbl, length: String(arr.base.length), elem: arr.elem };
    }
    if (arr.base.kind === 'memArray') {
      // a memory array local: the register holds a pointer to [len][elem0]... (dynamic outer).
      return {
        src: 'memory',
        ptr: this.ctxLookup(ctx, arr.base.varName),
        elem: arr.elem,
        fixedLen: arr.memFixedLen,
        staticElem: arr.memStaticElem,
      };
    }
    if (arr.base.kind === 'memArrayExpr') {
      // a memory array produced by an expression (a ternary, or a nested inner array m[i]): lower it
      // to its pointer. memFixedLen marks a FIXED outer (no [len] header) - e.g. an Arr<u256[],N> local
      // or a fixed inner reached by indexing.
      const ptr = this.fresh();
      out.push(`let ${ptr} := ${this.lowerExpr(arr.base.expr, ctx, out)}`);
      return { src: 'memory', ptr, elem: arr.elem, fixedLen: arr.memFixedLen, staticElem: arr.memStaticElem };
    }
    if (arr.base.kind === 'cdSubElem') {
      // a[i] inner array of a MIXED calldata composite. The param is bound as a calldata array
      // (b.offset, b.length, b.elem = the inner array type). Bound i against the outer count/N
      // (Panic 0x32), then resolve the inner array:
      //  - dynamic-of-fixed (inner is a fixed array): contiguous, stride = abiHeadWords(inner)*32;
      //    the inner fixed array starts at b.offset + i*stride (outer payload already validated).
      //  - fixed-of-dynamic (inner is a dynamic array): resolve via the offset table at b.offset
      //    (calldataInnerArray, with the same revert semantics as a nested dynamic array).
      const b = ctx.cdArrays.get(arr.base.name);
      if (!b) throw new UnsupportedError(`unbound calldata composite ${arr.base.name}`);
      const inner = b.elem;
      const i = this.fresh();
      out.push(`let ${i} := ${this.lowerExpr(arr.base.index, ctx, out)}`);
      out.push(`if iszero(lt(${i}, ${b.length})) { ${this.panic()}(0x32) }`);
      if (inner.kind === 'array' && inner.length !== undefined && isStaticType(inner)) {
        // dynamic array of STATIC fixed arrays (uint256[2][]): elements are contiguous, each one
        // abiHeadWords(inner) words. a[i] starts at b.offset + i*stride.
        const stride = abiHeadWords(inner) * 32;
        const offset = this.fresh();
        out.push(`let ${offset} := add(${b.offset}, mul(${i}, ${stride}))`);
        return { src: 'calldata', offset, length: String(inner.length), elem: arr.elem };
      }
      if (inner.kind === 'array' && inner.length !== undefined) {
        // dynamic array of a fixed-array-of-DYNAMIC (string[3][] = Arr<string,3>[]): element i is
        // VARIABLE-size and offset-located (NOT contiguous). a[i] is the element's N-word offset
        // table, which is itself offset-table-indexed by the next access.
        const offset = this.fresh();
        out.push(`let ${offset} := ${this.calldataNestedOff()}(${b.offset}, ${i})`);
        return { src: 'calldata', offset, length: String(inner.length), elem: arr.elem };
      }
      const stride = abiHeadWords(arr.elem) * 32;
      const nb = this.fresh();
      const nl = this.fresh();
      out.push(`let ${nb}, ${nl} := ${this.calldataInnerArray()}(${b.offset}, ${i}, ${stride})`);
      return { src: 'calldata', offset: nb, length: nl, elem: arr.elem };
    }
    if (arr.base.kind === 'cdNestedElem') {
      // Inner array m[i] of a nested dynamic array T[][] (calldata, 4e-5). The outer
      // param is decoded into (pointerRegionStart, outerLen); bounds-check i against
      // outerLen (Panic 0x32), then resolve inner i's (dataOffset, innerLen) through
      // its pointer-table word (base = pointerRegionStart, spec section 2). A pointer
      // / length / payload past calldatasize -> EMPTY revert inside the helper.
      const b = ctx.cdArrays.get(arr.base.name);
      if (!b) throw new UnsupportedError(`unbound nested calldata array ${arr.base.name}`);
      // Descend one ARRAY level per index, bounds-checking against the current level's count.
      // The element navigated at each step (elemT, starting at the root's immediate element b.elem)
      // determines the navigation: a DYNAMIC-array element (T[]) is offset+length (calldataInnerArray,
      // count = its read length); a FIXED-array-of-dynamic element (Arr<string,N>) is offset-only
      // (calldataNestedOff, count = the static N). Mixed nesting (string[2][3][]) descends correctly.
      const indices = arr.base.indices;
      let base = b.offset;
      let count: string = b.length; // count of the current container (runtime for dynamic, static N for fixed)
      let elemT: JethType = b.elem; // the element type navigated INTO at the current step
      indices.forEach((idxExpr) => {
        const i = this.fresh();
        out.push(`let ${i} := ${this.lowerExpr(idxExpr, ctx, out)}`);
        out.push(`if iszero(lt(${i}, ${count})) { ${this.panic()}(0x32) }`);
        if (elemT.kind === 'array' && elemT.length === undefined) {
          // navigate into a DYNAMIC array element: read its length word.
          const stride = isDynamicType(elemT.element) ? 32 : abiHeadWords(elemT.element) * 32;
          const nb = this.fresh();
          const nl = this.fresh();
          out.push(`let ${nb}, ${nl} := ${this.calldataInnerArray()}(${base}, ${i}, ${stride})`);
          base = nb;
          count = nl;
        } else if (elemT.kind === 'array' && elemT.length !== undefined) {
          // navigate into a FIXED-array-of-dynamic element: offset only, count = its static length.
          const nb = this.fresh();
          out.push(`let ${nb} := ${this.calldataNestedOff()}(${base}, ${i})`);
          base = nb;
          count = String(elemT.length);
        } else {
          throw new UnsupportedError(`cannot index calldata nested element of kind '${elemT.kind}'`);
        }
        elemT = (elemT as JethType & { kind: 'array' }).element;
      });
      return { src: 'calldata', offset: base, length: count, elem: arr.elem };
    }
    if (arr.base.kind === 'cdSlice') {
      // P1-8: a calldata array slice a[start:end]. Resolve the base array's (offset, length), then narrow:
      // offset' = offset + start*stride, length' = end - start (stride = the element's contiguous ABI
      // width). Bounds: require(start <= end && end <= length) else EMPTY-revert, byte-identical to solc.
      // Order matches solc left-to-right operand evaluation: base, then start, then end.
      const inner = this.lowerArrayRef(arr.base.base, ctx, out);
      if (inner.src !== 'calldata') throw new UnsupportedError('a calldata array slice base must be calldata');
      const baseOff = this.fresh();
      const baseLen = this.fresh();
      out.push(`let ${baseOff} := ${inner.offset}`);
      out.push(`let ${baseLen} := ${inner.length}`);
      const start = this.fresh();
      out.push(`let ${start} := ${this.lowerExpr(arr.base.start, ctx, out)}`);
      const end = this.fresh();
      if (arr.base.end) out.push(`let ${end} := ${this.lowerExpr(arr.base.end, ctx, out)}`);
      else out.push(`let ${end} := ${baseLen}`);
      out.push(`if gt(${start}, ${end}) { revert(0, 0) }`);
      out.push(`if gt(${end}, ${baseLen}) { revert(0, 0) }`);
      const stride = abiHeadWords(arr.elem) * 32;
      const offset = this.fresh();
      const length = this.fresh();
      out.push(`let ${offset} := add(${baseOff}, mul(${start}, ${stride}))`);
      out.push(`let ${length} := sub(${end}, ${start})`);
      return { src: 'calldata', offset, length, elem: arr.elem };
    }
    const b = ctx.cdArrays.get(arr.base.name);
    if (!b) throw new UnsupportedError(`unbound calldata array ${arr.base.name}`);
    return { src: 'calldata', offset: b.offset, length: b.length, elem: arr.elem };
  }

  private arrayDataSlot(lenSlot: string, out: string[]): string {
    const d = this.fresh();
    out.push(`let ${d} := ${this.arrayDataSlotHelper()}(${lenSlot})`);
    return d;
  }

  private lowerArrayGet(e: Expr & { kind: 'arrayGet' }, ctx: LowerCtx, out: string[]): string {
    const ref = this.lowerArrayRef(e.arr, ctx, out);
    const i = this.fresh();
    out.push(`let ${i} := ${this.lowerExpr(e.index, ctx, out)}`);
    // @public auto-getters revert with EMPTY data on out-of-bounds (matching solc's getter),
    // whereas an ordinary a[i] access raises Panic(0x32).
    const oob = e.oobEmpty ? 'revert(0, 0)' : `${this.panic()}(0x32)`;
    if (ref.src === 'storage') {
      out.push(`if iszero(lt(${i}, sload(${ref.lenSlot}))) { ${oob} }`);
      const data = this.arrayDataSlot(ref.lenSlot, out);
      return this.arrayElemLoad(ref.elem, data, i);
    }
    if (ref.src === 'fixed') {
      out.push(`if iszero(lt(${i}, ${ref.length})) { ${oob} }`);
      return this.arrayElemLoad(ref.elem, String(ref.baseSlot), i); // data inline at baseSlot
    }
    if (ref.src === 'memory') {
      // bound: a DYNAMIC outer has a [len] header word (mload(ptr)); a FIXED outer (ref.fixedLen)
      // bounds against the constant N and has NO header (data starts at ptr).
      const bound = ref.fixedLen !== undefined ? String(ref.fixedLen) : `mload(${ref.ptr})`;
      out.push(`if iszero(lt(${i}, ${bound})) { ${oob} }`);
      const dataBase = ref.fixedLen !== undefined ? ref.ptr : `add(${ref.ptr}, 0x20)`;
      // an ARRAY or STRUCT element: a STATIC inline VALUE-array sub-image yields a BASE pointer
      // (dataBase + i*ew, ew = abiHeadWords words, staticElem = true); a POINTER-HEADED element word
      // (Cat B static struct; a DYNAMIC bytes/string/inner-array element) holds the absolute pointer to
      // the inner image (mload(dataBase + i*0x20)).
      if (ref.elem.kind === 'array' || ref.elem.kind === 'struct') {
        const ew = abiHeadWords(ref.elem) * 32;
        if (ref.staticElem) return `add(${dataBase}, mul(${i}, ${ew}))`;
        return `mload(add(${dataBase}, mul(${i}, 0x20)))`;
      }
      // a value element: one word per element at dataBase + i*32.
      // W6C: an ENUM element read from memory is range-checked (Panic 0x21, solc's
      // read_from_memory validator_assert): the image may hold RAW dirty words from the
      // calldata bind/slice copy (which, like solc, does NOT validate enums during the copy).
      const en = this.enumCount(ref.elem);
      if (en !== undefined) {
        const w = this.fresh();
        out.push(`let ${w} := mload(add(${dataBase}, mul(${i}, 0x20)))`);
        out.push(`if iszero(lt(${w}, ${en})) { ${this.panic()}(0x21) }`);
        return w;
      }
      return `mload(add(${dataBase}, mul(${i}, 0x20)))`;
    }
    out.push(`if iszero(lt(${i}, ${ref.length})) { ${oob} }`);
    const w = this.fresh();
    out.push(`let ${w} := calldataload(add(${ref.offset}, mul(${i}, 32)))`);
    const guard = this.validateInput(ref.elem, w); // validate dirty calldata elements on read
    if (guard) out.push(guard);
    return w;
  }

  /** Write a whole inner array into element i of a NESTED MEMORY array local (m[i] = <array>). The
   *  mirror of the lowerArrayGet memory branch: a DYNAMIC inner element is one absolute-pointer word
   *  (store the materialized RHS pointer, a reference assignment exactly like solc); a STATIC inner
   *  element is an inline sub-block (copy the RHS image's words in). RHS materialized FIRST (solc
   *  evaluates the value before the LHS location); i is bound-checked (Panic 0x32). */
  private writeNestedMemArrayElem(
    target: LValue & { kind: 'arrayElem' },
    value: Expr,
    ctx: LowerCtx,
    out: string[],
  ): void {
    const innerT = target.type as JethType & { kind: 'array' };
    // Keep the inline-copy branch ONLY for a fully-fixed VALUE-WORD inner (Arr<u256,N>, Arr<Arr<u256,2>,2>,
    // and FIX: Arr<(x)=>R,N>): it stays an inline sub-block in the outer image. Re-point (a reference
    // assignment) for any other inner that is POINTER-HEADED in the outer image: a DYNAMIC inner (u256[],
    // bytes[], P[], ((x)=>R)[]) OR a static array whose ultimate leaf is a struct (Cat B: Arr<P,N>, which
    // isInlineValueWordElem excludes via !isPointerHeadedStaticElem).
    const inlineValueArrayInner = isInlineValueWordElem(innerT);
    if (!inlineValueArrayInner) {
      // pointer-headed inner: materialize -> pointer, store at the element word (reference assignment).
      // Use aggArgToMemPtr so a memory-reference RHS (xs[i] = xs[j], or = a bytes[]/u256[]/P[] local)
      // ALIASES by storing its pointer (matching solc memory references), while a literal / calldata /
      // storage source is materialized/copied to a fresh image - exactly the binding path's resolution.
      const p = this.fresh();
      out.push(`let ${p} := ${this.aggArgToMemPtr(value, ctx, out)}`);
      const ref = this.lowerArrayRef(target.arr, ctx, out); // src 'memory'
      if (ref.src !== 'memory') throw new UnsupportedError('nested memory-array element write requires a memory array');
      const i = this.fresh();
      out.push(`let ${i} := ${this.lowerExpr(target.index, ctx, out)}`);
      const bound = ref.fixedLen !== undefined ? String(ref.fixedLen) : `mload(${ref.ptr})`;
      out.push(`if iszero(lt(${i}, ${bound})) { ${this.panic()}(0x32) }`);
      const dataBase = ref.fixedLen !== undefined ? ref.ptr! : `add(${ref.ptr}, 0x20)`;
      out.push(`mstore(add(${dataBase}, mul(${i}, 0x20)), ${p})`);
      return;
    }
    // static inline VALUE-array inner (Arr<value,N>): materialize the RHS image, then copy its
    // ew bytes (abiHeadWords words, the inline element width) into element i's inline sub-block.
    const ew = abiHeadWords(innerT) * 32;
    const src = this.fresh();
    out.push(`let ${src} := ${this.aggToMemPtr(value, ctx, out)}`);
    const ref = this.lowerArrayRef(target.arr, ctx, out);
    if (ref.src !== 'memory') throw new UnsupportedError('nested memory-array element write requires a memory array');
    const i = this.fresh();
    out.push(`let ${i} := ${this.lowerExpr(target.index, ctx, out)}`);
    const bound = ref.fixedLen !== undefined ? String(ref.fixedLen) : `mload(${ref.ptr})`;
    out.push(`if iszero(lt(${i}, ${bound})) { ${this.panic()}(0x32) }`);
    const dataBase = ref.fixedLen !== undefined ? ref.ptr! : `add(${ref.ptr}, 0x20)`;
    const dst = this.fresh();
    out.push(`let ${dst} := add(${dataBase}, mul(${i}, ${ew}))`);
    for (let k = 0; k < ew / 32; k++) out.push(`mstore(add(${dst}, ${k * 32}), mload(add(${src}, ${k * 32})))`);
  }

  /** Load array element i (register form) from storage data base `dataSlot`. */
  private arrayElemLoad(elem: JethType, dataSlot: string, iExpr: string): string {
    const packs = arrayElemPacks(elem);
    if (!packs.packed) return this.loadState(elem, `add(${dataSlot}, ${iExpr})`, 0);
    const slot = `add(${dataSlot}, div(${iExpr}, ${packs.perSlot}))`;
    const byteOff = `mul(mod(${iExpr}, ${packs.perSlot}), ${packs.size})`;
    return this.packedLoad(elem, slot, byteOff);
  }

  private arrayElemStore(elem: JethType, dataSlot: string, iExpr: string, value: string, out: string[]): void {
    const packs = arrayElemPacks(elem);
    if (!packs.packed) {
      for (const l of this.storeState(elem, `add(${dataSlot}, ${iExpr})`, 0, value)) out.push(l);
      return;
    }
    const st = this.fresh();
    out.push(`let ${st} := add(${dataSlot}, div(${iExpr}, ${packs.perSlot}))`);
    const byteOff = `mul(mod(${iExpr}, ${packs.perSlot}), ${packs.size})`;
    this.packedStore(elem, st, byteOff, value, out);
  }

  private packedLoad(elem: JethType, slot: string, byteOff: string): string {
    const { size } = arrayElemPacks(elem);
    const mask = toWord((1n << BigInt(size * 8)) - 1n);
    const raw = `shr(mul(${byteOff}, 8), sload(${slot}))`;
    if (elem.kind === 'int') return `signextend(${size - 1}, ${raw})`;
    if (elem.kind === 'bytesN') return `shl(${(32 - size) * 8}, and(${raw}, ${mask}))`;
    return `and(${raw}, ${mask})`;
  }

  private packedStore(elem: JethType, slot: string, byteOff: string, value: string, out: string[]): void {
    const { size } = arrayElemPacks(elem);
    const mask = toWord((1n << BigInt(size * 8)) - 1n);
    const fieldData = elem.kind === 'bytesN' ? `shr(${(32 - size) * 8}, ${value})` : value;
    const bit = this.fresh();
    out.push(`let ${bit} := mul(${byteOff}, 8)`);
    const cleared = this.fresh();
    out.push(`let ${cleared} := and(sload(${slot}), not(shl(${bit}, ${mask})))`);
    out.push(`sstore(${slot}, or(${cleared}, shl(${bit}, and(${fieldData}, ${mask}))))`);
  }

  private lowerPush(arr: ArrayExpr, value: Expr | undefined, ctx: LowerCtx, out: string[]): void {
    const ref = this.lowerArrayRef(arr, ctx, out);
    if (ref.src !== 'storage') throw new UnsupportedError('push on a non-storage array');
    // W7B (arg-first): FREEZE the pushed value BEFORE the grow - a lazy value expression (an
    // sload like sa.push(sa.length), or an internal call sa.push(this.rd())) must read the OLD
    // length, exactly like solc's argument-before-push evaluation. The base ref (mapping keys)
    // was already resolved above, preserving solc's left-to-right base-then-argument order.
    let v = '0';
    if (value) {
      const reg = this.fresh();
      out.push(`let ${reg} := ${this.lowerExpr(value, ctx, out)}`);
      v = reg;
    }
    const len = this.fresh();
    out.push(`let ${len} := sload(${ref.lenSlot})`);
    out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
    out.push(`sstore(${ref.lenSlot}, add(${len}, 1))`);
    const data = this.arrayDataSlot(ref.lenSlot, out);
    this.arrayElemStore(ref.elem, data, len, v, out);
  }

  /** push a whole inner array onto a nested storage array (this.dd.push(xs) on a T[][]):
   *  grow the outer length, then deep-copy the pushed array value into the freshly grown
   *  inner element (its length slot is at data + len*stride, fresh = empty). A no-arg
   *  push() leaves the inner array empty (length 0). */
  private lowerArrayPush(arr: ArrayExpr, value: Expr | undefined, ctx: LowerCtx, out: string[]): void {
    const ref = this.lowerArrayRef(arr, ctx, out);
    if (ref.src !== 'storage') throw new UnsupportedError('push on a non-storage array');
    const elem = arr.elem as JethType & { kind: 'array' };
    // W5A/W7B (arg-first): solc evaluates the push ARGUMENT before the push operation itself, so
    // EVERY source handle is resolved BEFORE the length grow - a memory source (an array literal
    // with side-effecting elements, or a memory/calldata aggregate) is materialized first, and a
    // STORAGE source's location (including any element bounds check: dd.push(dd[0]) on an empty
    // array panics like solc - P12/P33) is resolved first. The copy itself runs after the grow,
    // reading the already-resolved handle (the grown region never overlaps a valid source).
    let memSrc: string | undefined;
    let litPrep: PreparedLitElem[] | undefined;
    let fixedSrcBase: string | undefined;
    if (value && elem.length !== undefined) {
      // W6A: the pushed element image is deep-copied into storage right below - a TRANSIENT
      // capture context, so an aliasable memory element source inside a literal stays accepted.
      memSrc = this.inTransientCapture(() => {
        if (value.kind === 'arrayLit')
          return isDynLeafFixedArray(elem)
            ? this.buildNestedMemArrayLit(value, ctx, out)
            : isStaticType(elem) && isInlineValueWordElem(elem.element)
              ? this.allocAggToMem(value, ctx, out)
              : undefined;
        if (value.kind === 'memAggregate' || value.kind === 'cdAggregateValue')
          return this.aggToMemPtr(value, ctx, out);
        return undefined;
      });
      if (memSrc === undefined) {
        if (value.kind === 'arrayLit') litPrep = this.prepareLitElems(value, ctx, out);
        else fixedSrcBase = this.fixedArraySrcBase(value, ctx, out);
      }
    }
    let dynPrep: { k: 'stor'; srcLenSlot: string } | { k: 'mem'; ptr: string } | { k: 'cd' } | undefined;
    if (value && elem.length === undefined) {
      const storageSrc =
        value.kind === 'mapStorageValue' ||
        (value.kind === 'arrayValue' &&
          (value.arr.base.kind === 'stateArray' ||
            value.arr.base.kind === 'mapArray' ||
            value.arr.base.kind === 'placeArray'));
      if (storageSrc) dynPrep = { k: 'stor', srcLenSlot: this.arraySrcLenSlot(value, ctx, out) };
      else if (value.kind === 'arrayValue' && value.arr.base.kind === 'calldataArray') dynPrep = { k: 'cd' };
      else {
        const p = this.fresh();
        out.push(`let ${p} := ${this.lowerExpr(value, ctx, out)}`);
        dynPrep = { k: 'mem', ptr: p };
      }
    }
    const stride = storageSlotCount(arr.elem); // a dynamic-array inner element occupies 1 slot
    const len = this.fresh();
    out.push(`let ${len} := sload(${ref.lenSlot})`);
    out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
    out.push(`sstore(${ref.lenSlot}, add(${len}, 1))`);
    const dataBase = this.fresh();
    out.push(`let ${dataBase} := ${this.arrayDataSlotHelper()}(${ref.lenSlot})`);
    const innerSlot = this.fresh();
    out.push(`let ${innerSlot} := add(${dataBase}, mul(${len}, ${stride}))`);
    if (elem.length !== undefined) {
      // a FIXED inner array element (Arr<T,N>[]): the element is N inline words at innerSlot, NOT a
      // dynamic array with its own length slot. Write the literal / copy the source fixed array
      // inline. (A no-arg push() grows with a zero element; the fresh slots are already 0.)
      // W5A: a MEMORY / CALLDATA source (memSrc above) routes through the same codecs the whole-array
      // assign uses (storeDynLeafFixedArrayFromMem for a dyn-leaf element, storeStaticAggFromMem for a
      // flat static one), byte-identical to solc's `g3.push(a)`. The fresh element's slots are zero, so
      // the codecs' overwrite-clear is a no-op there.
      if (value) {
        if (memSrc !== undefined) {
          if (isDynLeafFixedArray(elem)) this.storeDynLeafFixedArrayFromMem(elem, memSrc, innerSlot, out);
          else this.storeStaticAggFromMem(elem, memSrc, innerSlot, out);
        } else if (litPrep !== undefined) {
          this.emitPreparedLitStore(value as Expr & { kind: 'arrayLit' }, litPrep, innerSlot, out);
        } else if (fixedSrcBase !== undefined) {
          this.copyFixedArray(elem, fixedSrcBase, innerSlot, out);
        }
      }
      return;
    }
    // a DYNAMIC inner array element (T[][]): innerSlot is the inner array's length slot.
    if (value && dynPrep) {
      if (dynPrep.k === 'stor') this.copyArray(elem.element, dynPrep.srcLenSlot, innerSlot, out);
      else if (dynPrep.k === 'mem') {
        if (isValueWord(elem.element)) this.copyMemArrayIntoStorage(elem.element, dynPrep.ptr, innerSlot, out);
        else if (isBytesLike(elem.element) || elem.element.kind === 'array')
          this.copyMemAggArrayIntoStorage(elem.element, dynPrep.ptr, innerSlot, out);
        else throw new UnsupportedError('a memory array of non-value elements is not supported');
      } else {
        // a CALLDATA value-array source: immutable input; the validated decode+store loop runs
        // here (any validation panic rolls the grow back, revert data identical to solc's).
        this.copyArrayValueIntoStorage(elem.element, value, innerSlot, ctx, out);
      }
    }
  }

  /** Deep-copy an ARRAY VALUE (memory `memArray`/`arrayLit` of value elements, or a
   *  storage `stateArray`/`mapArray`) into a storage dynamic array at `dstLenSlot`. Clears
   *  the dst's OLD data first (so it works for both a fresh push slot, oldLen 0 = no-op,
   *  and an overwrite assign), then sets the length and copies every element. */
  private copyArrayValueIntoStorage(
    innerElem: JethType,
    value: Expr,
    dstLenSlot: string,
    ctx: LowerCtx,
    out: string[],
  ): void {
    const storageSrc =
      value.kind === 'mapStorageValue' ||
      (value.kind === 'arrayValue' &&
        (value.arr.base.kind === 'stateArray' ||
          value.arr.base.kind === 'mapArray' ||
          value.arr.base.kind === 'placeArray'));
    if (storageSrc) {
      this.copyArray(innerElem, this.arraySrcLenSlot(value, ctx, out), dstLenSlot, out);
      return;
    }
    // calldata source (a calldata value-array param: this.a = p): decode + validate each element
    // (like solc's per-element calldata read) and packed-store into storage. Value elements only.
    if (value.kind === 'arrayValue' && value.arr.base.kind === 'calldataArray') {
      if (!isStaticValueType(innerElem))
        throw new UnsupportedError('a calldata array of non-value elements is not supported');
      const b = ctx.cdArrays.get(value.arr.base.name);
      if (!b) throw new UnsupportedError(`unbound calldata array ${value.arr.base.name}`);
      const dstData = this.fresh();
      out.push(`let ${dstData} := ${this.arrayDataSlotHelper()}(${dstLenSlot})`);
      const packs = arrayElemPacks(innerElem);
      const slotsFor = (L: string): string =>
        packs.packed
          ? `div(add(${L}, ${packs.perSlot - 1}), ${packs.perSlot})`
          : `mul(${L}, ${storageSlotCount(innerElem)})`;
      const oldSlots = this.fresh();
      out.push(`let ${oldSlots} := ${slotsFor(`sload(${dstLenSlot})`)}`);
      const c = this.fresh();
      out.push(
        `for { let ${c} := 0 } lt(${c}, ${oldSlots}) { ${c} := add(${c}, 1) } { sstore(add(${dstData}, ${c}), 0) }`,
      );
      out.push(`sstore(${dstLenSlot}, ${b.length})`);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${b.length}) { ${i} := add(${i}, 1) } {`);
      const inner: string[] = [];
      const w = this.fresh();
      inner.push(`let ${w} := calldataload(add(${b.offset}, mul(${i}, 32)))`);
      const guard = this.validateInput(innerElem, w);
      if (guard) inner.push(guard);
      this.arrayElemStore(innerElem, dstData, i, w, inner);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
      return;
    }
    // memory source (a memArray local, a nested array literal, or new Array<T>(n)).
    const memPtr = this.lowerExpr(value, ctx, out);
    // isValueWord: a value leaf OR a funcref leaf (FIX nested funcref: a funcref inner element is one
    // word - its id - stored exactly like a uint256 element; e.g. this.g.push([this.a, this.b]) where
    // g: ((x)=>R)[][]). copyMemArrayIntoStorage packs/stores the word elements identically.
    if (isValueWord(innerElem)) {
      this.copyMemArrayIntoStorage(innerElem, memPtr, dstLenSlot, out);
      return;
    }
    // a NON-VALUE element (bytes/string, or a nested dynamic array): the memory image is
    // pointer-headed ([len] + per-element absolute pointers, the same B4 image JETH builds for
    // bytes[][]/string[][]/u256[][] memory locals). Deep-copy it recursively into storage (each
    // dynamic element gets its own keccak-located data region). Byte-identical to solc.
    if (isBytesLike(innerElem) || innerElem.kind === 'array') {
      this.copyMemAggArrayIntoStorage(innerElem, memPtr, dstLenSlot, out);
      return;
    }
    throw new UnsupportedError('a memory array of non-value elements is not supported');
  }

  /** Deep-copy a MEMORY pointer-headed aggregate array image ([len] header at `memPtr`, then `len`
   *  absolute-pointer words) into a storage dynamic array at `dstLenSlot` (length there, data at
   *  keccak(slot)). The element `innerElem` is a NON-VALUE type: bytes/string (each element pointer
   *  -> a [len][data] blob, written with the storage bytes/string writer) or a nested dynamic array
   *  (recurse one level - the inner storage element is itself a dynamic array at its own keccak
   *  region). Mirrors copyArray's dynamic-element path (deep-clear the shrink range, set length,
   *  overwrite-copy [0,len)) so it is correct for a fresh push slot AND a reused/stale slot. */
  private copyMemAggArrayIntoStorage(innerElem: JethType, memPtr: string, dstLenSlot: string, out: string[]): void {
    const srcLen = this.fresh();
    out.push(`let ${srcLen} := mload(${memPtr})`);
    const dstLen = this.fresh();
    out.push(`let ${dstLen} := sload(${dstLenSlot})`);
    const dstData = this.fresh();
    out.push(`let ${dstData} := ${this.arrayDataSlotHelper()}(${dstLenSlot})`);
    const sc = storageSlotCount(innerElem); // a dynamic element occupies 1 slot (its header/length slot)
    // deep-clear elements [srcLen, dstLen) that will be dropped (frees their keccak-located tails).
    const k = this.fresh();
    out.push(`for { let ${k} := ${srcLen} } lt(${k}, ${dstLen}) { ${k} := add(${k}, 1) } {`);
    const clearInner: string[] = [];
    const ceb = this.fresh();
    clearInner.push(`let ${ceb} := add(${dstData}, mul(${k}, ${sc}))`);
    this.deleteAgg(innerElem, ceb, clearInner);
    for (const l of clearInner) out.push('  ' + l);
    out.push('}');
    out.push(`sstore(${dstLenSlot}, ${srcLen})`);
    // overwrite-copy [0, srcLen): each element pointer in the image -> a deep storage write.
    const m = this.fresh();
    out.push(`for { let ${m} := 0 } lt(${m}, ${srcLen}) { ${m} := add(${m}, 1) } {`);
    const copyInner: string[] = [];
    const eptr = this.fresh();
    copyInner.push(`let ${eptr} := mload(add(${memPtr}, add(0x20, mul(${m}, 0x20))))`);
    const deb = this.fresh();
    copyInner.push(`let ${deb} := add(${dstData}, mul(${m}, ${sc}))`);
    if (isBytesLike(innerElem)) {
      // a string/bytes element: the image pointer addresses a [len][data] blob. The storage
      // bytes/string writer overwrite-clears its own old tail, so a stale dst element is handled.
      copyInner.push(`${this.storeStrMem()}(${deb}, ${eptr}, mload(${eptr}))`);
    } else {
      // a nested dynamic-array element (string[][]'s string[], u256[][][]'s u256[][]): recurse.
      const inner = (innerElem as JethType & { kind: 'array' }).element;
      if (isStaticValueType(inner)) this.copyMemArrayIntoStorage(inner, eptr, deb, copyInner);
      else this.copyMemAggArrayIntoStorage(inner, eptr, deb, copyInner);
    }
    for (const l of copyInner) out.push('  ' + l);
    out.push('}');
  }

  /** Deep-copy a MEMORY value-element array ([len][elems] at `memPtr`) into a storage dynamic array
   *  at `dstLenSlot` (length there, data at keccak(slot)): resize + clear old data + packed element
   *  store. Shared by whole-array assignment and a dynamic-array struct field write. */
  private copyMemArrayIntoStorage(innerElem: JethType, memPtr: string, dstLenSlot: string, out: string[]): void {
    const n = this.fresh();
    out.push(`let ${n} := mload(${memPtr})`);
    const dstData = this.fresh();
    out.push(`let ${dstData} := ${this.arrayDataSlotHelper()}(${dstLenSlot})`);
    const packs = arrayElemPacks(innerElem);
    const slotsFor = (L: string): string =>
      packs.packed
        ? `div(add(${L}, ${packs.perSlot - 1}), ${packs.perSlot})`
        : `mul(${L}, ${storageSlotCount(innerElem)})`;
    const oldSlots = this.fresh();
    out.push(`let ${oldSlots} := ${slotsFor(`sload(${dstLenSlot})`)}`);
    const c = this.fresh();
    out.push(
      `for { let ${c} := 0 } lt(${c}, ${oldSlots}) { ${c} := add(${c}, 1) } { sstore(add(${dstData}, ${c}), 0) }`,
    );
    out.push(`sstore(${dstLenSlot}, ${n})`);
    const i = this.fresh();
    out.push(`for { let ${i} := 0 } lt(${i}, ${n}) { ${i} := add(${i}, 1) } {`);
    const inner: string[] = [];
    const me = this.fresh();
    inner.push(`let ${me} := mload(add(${memPtr}, add(0x20, mul(${i}, 0x20))))`);
    // W6C: a memory->storage ENUM element copy range-checks each word (Panic 0x21, solc's
    // read-from-memory validation) - the image may hold RAW dirty words from a calldata bind.
    // Without this the packed store would MASK a dirty word into a bogus valid member.
    const en = this.enumCount(innerElem);
    if (en !== undefined) inner.push(`if iszero(lt(${me}, ${en})) { ${this.panic()}(0x21) }`);
    this.arrayElemStore(innerElem, dstData, i, me, inner);
    for (const l of inner) out.push('  ' + l);
    out.push('}');
  }

  private lowerPop(arr: ArrayExpr, ctx: LowerCtx, out: string[]): void {
    const ref = this.lowerArrayRef(arr, ctx, out);
    if (ref.src !== 'storage') throw new UnsupportedError('pop on a non-storage array');
    const len = this.fresh();
    out.push(`let ${len} := sload(${ref.lenSlot})`);
    out.push(`if iszero(${len}) { ${this.panic()}(0x31) }`);
    const nl = this.fresh();
    out.push(`let ${nl} := sub(${len}, 1)`);
    out.push(`sstore(${ref.lenSlot}, ${nl})`);
    const data = this.arrayDataSlot(ref.lenSlot, out);
    const sc = storageSlotCount(ref.elem);
    if (isDynamicType(ref.elem)) {
      // the freed element holds DYNAMIC data (a dynamic array / bytes / string / dynamic struct /
      // fixed-array-of-dynamic). Its storage footprint includes keccak-located data slots that a plain
      // header-zero leaves STALE (so stale data resurfaces when the index is reused). DEEP-CLEAR it via
      // the same recursive footprint clear `delete` uses, so it is byte-identical to solc's pop().
      const base = this.fresh();
      out.push(`let ${base} := add(${data}, mul(${nl}, ${sc}))`);
      this.deleteAgg(ref.elem, base, out);
    } else if (sc === 1) {
      // value element, or a fixed array that packs into ONE slot (uint8[4], uint128[2]):
      // arrayElemStore handles per-byte packing / single-slot clear.
      this.arrayElemStore(ref.elem, data, nl, '0', out);
    } else {
      // a MULTI-slot STATIC fixed-array element (uint256[2], uint256[2][2], ...): solc zeroes ALL
      // sc slots of the freed element; clear each contiguous slot at data + nl*sc.
      const base = this.fresh();
      out.push(`let ${base} := add(${data}, mul(${nl}, ${sc}))`);
      for (let k = 0; k < sc; k++) out.push(`sstore(${k === 0 ? base : `add(${base}, ${k})`}, 0)`);
    }
  }

  /** push a struct element onto a storage dynamic array: grow length, then write
   *  each field of the appended element (Solidity packs fields within its slots).
   *  A no-value push zero-initializes the new element's slots. */
  private lowerStructPush(arr: ArrayExpr, value: Expr | undefined, ctx: LowerCtx, out: string[]): void {
    const ref = this.lowerArrayRef(arr, ctx, out);
    if (ref.src !== 'storage') throw new UnsupportedError('push on a non-storage array');
    const struct = arr.elem as JethType & { kind: 'struct' };
    const slots = storageSlotCount(struct);
    // W7B (arg-first): solc evaluates the push ARGUMENT completely BEFORE the grow - a ctor arg
    // reading ps.length sees the OLD length (A8), and ps.push(ps[0]) on an empty array panics on
    // the source bounds check (P10) instead of aliasing the freshly-grown element. The prepared
    // value dispatches every source kind - a constructor (prepared ctor args), a static struct
    // local/param (storeStaticAggFromMem), a dynamic-field struct from a memory local / calldata
    // param / nested-dyn-struct field (writeDynStructFromMem), or a storage struct (copyStruct).
    // (Previously only a structNew was written and every other source silently stored a zero
    // element - a miscompile.)
    const prep = value ? this.prepareStructStore(struct, value, ctx, out) : undefined;
    const len = this.fresh();
    out.push(`let ${len} := sload(${ref.lenSlot})`);
    out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
    out.push(`sstore(${ref.lenSlot}, add(${len}, 1))`);
    const dataBase = this.fresh();
    out.push(`let ${dataBase} := ${this.arrayDataSlotHelper()}(${ref.lenSlot})`);
    const base = this.fresh();
    out.push(`let ${base} := add(${dataBase}, mul(${len}, ${slots}))`);
    if (prep) {
      this.emitPreparedStructStore(struct, prep, base, out);
    } else {
      // arr.push() with no argument: append a default (all-zero) element.
      for (let j = 0; j < slots; j++) out.push(`sstore(${j === 0 ? base : `add(${base}, ${j})`}, 0)`);
    }
  }

  /** Write a struct value (from a structNew, possibly with nested-struct field
   *  args) into storage starting at `baseSlot` (a constant-numeric string or a
   *  register expr). Nested structs are flattened recursively into packed slots;
   *  value fields go through storeState (handles packing / whole-slot); a
   *  bytes/string dynamic field at slotAt(f.slot) goes through storeDynamic (a
   *  normal storage bytes/string, overwrite-clearing the old tail, byte-identical
   *  to solc).
   *  W7B (TWO-PHASE): solc materializes the constructed value in MEMORY first (every ctor
   *  argument evaluated in source order) and only then copies it into storage - a later
   *  argument that reads the destination sees the OLD data, and the overwrite-clear of an
   *  old dynamic tail also happens after all arguments ran. prepareCtorArgs captures each
   *  argument at its position (values frozen to registers, storage/calldata reference
   *  sources snapshotted to memory - solc's conversion-at-construction - memory reference
   *  sources aliased for the late read); emitPreparedCtorStore then performs every storage
   *  write. Previously the two were interleaved field-by-field, a confirmed miscompile. */
  private writeStruct(fields: StructField[], args: Expr[], baseSlot: string, ctx: LowerCtx, out: string[]): void {
    // W6A: every writeStruct caller writes the constructed value straight into STORAGE (state /
    // mapping / place / push), a deep copy in solc too - a TRANSIENT capture context, so an
    // aliasable memory field source stays accepted (internal-call args re-force persistent).
    const items = this.inTransientCapture(() => this.prepareCtorArgs(fields, args, ctx, out));
    this.emitPreparedCtorStore(fields, items, baseSlot, out);
  }

  /** W7B phase 1: evaluate every ctor argument in source order, capturing a store-ready handle
   *  per field (NO destination slot is touched). Mirrors the old field dispatch branch-for-branch;
   *  each captured handle feeds the matching store codec in emitPreparedCtorStore. */
  private prepareCtorArgs(fields: StructField[], args: Expr[], ctx: LowerCtx, out: string[]): PreparedFieldArg[] {
    return fields.map((f, i) => {
      const arg = args[i]!;
      if (f.type.kind === 'struct' && arg.kind === 'structNew') {
        // a nested constructor evaluates its own args at ITS position (recursively two-phase).
        return { k: 'ctor' as const, fields: arg.fields, items: this.prepareCtorArgs(arg.fields, arg.args, ctx, out) };
      }
      if (f.type.kind === 'struct' && isDynamicType(f.type)) {
        // W6A: a DYNAMIC struct field from a NON-INLINE source: materialize the source's
        // pointer-headed image (buildDynStructLocal ALIASES a memory source - the phase-2 write
        // reads it LATE, Solidity memory-reference semantics; copies storage/calldata at this
        // position - solc's conversion-at-construction).
        return { k: 'dynStruct' as const, ptr: this.buildDynStructLocal(f.type, arg, ctx, out) };
      }
      if (f.type.kind === 'array' && f.type.length === undefined) {
        return this.prepareDynArrayFieldArg(f.type, arg, ctx, out);
      }
      if (f.type.kind === 'array' && f.type.length !== undefined && isDynLeafFixedArray(f.type)) {
        // W5C: a FIXED-outer DYNAMIC-element field (Arr<string,N>): materialize the arg's N-pointer
        // memory image (a literal via buildNestedMemArrayLit inside aggArgToMemPtr; a memory local
        // ALIASES - late read; a storage/calldata source deep-copies here).
        return { k: 'dynLeafFixed' as const, ptr: this.aggArgToMemPtr(arg, ctx, out) };
      }
      if (f.type.kind === 'array' && arg.kind === 'arrayLit') {
        // a fixed-array field constructed from a (possibly nested) literal: evaluate every element
        // at this position; the stores run in phase 2.
        return { k: 'lit' as const, lit: arg, items: this.prepareLitElems(arg, ctx, out) };
      }
      if ((f.type.kind === 'struct' || (f.type.kind === 'array' && f.type.length !== undefined)) && isStaticType(f.type)) {
        // a non-inline STATIC aggregate field source: aggToMemPtr aliases a memory source (late
        // read) and copies a storage/calldata source here (solc's conversion-at-construction).
        return { k: 'staticAgg' as const, ptr: this.aggToMemPtr(arg, ctx, out) };
      }
      if (isBytesLike(f.type)) {
        // solc converts a STORAGE / CALLDATA bytes source to memory at the ARG position (P8: a
        // sibling that mutates the storage source afterwards must not change the stored value);
        // a memory ref (incl. a literal blob) is captured as-is and read late.
        let ref = this.lowerDynamic(arg, ctx, out);
        if (ref.src !== 'memory') ref = { src: 'memory', ptr: this.toMemory(ref, out).mp };
        return { k: 'bytes' as const, ref };
      }
      // a VALUE field: freeze the arg NOW (a lazy sload/internal-call expr must read at its own
      // source position, not at store time - P20).
      const reg = this.fresh();
      out.push(`let ${reg} := ${this.lowerExpr(arg, ctx, out)}`);
      return { k: 'value' as const, reg };
    });
  }

  /** W7B phase 1 for a DYNAMIC-array ctor field: capture the source per solc's construction
   *  semantics - a MEMORY source is captured BY POINTER (the phase-2 copy reads it late, P9b);
   *  a STORAGE source is snapshotted to a fresh memory image at this position (P27/P35); a
   *  CALLDATA value-array is decoded + validated into a fresh image here. */
  private prepareDynArrayFieldArg(
    t: JethType & { kind: 'array' },
    value: Expr,
    ctx: LowerCtx,
    out: string[],
  ): PreparedFieldArg {
    const innerElem = t.element;
    const storageSrc =
      value.kind === 'mapStorageValue' ||
      (value.kind === 'arrayValue' &&
        (value.arr.base.kind === 'stateArray' ||
          value.arr.base.kind === 'mapArray' ||
          value.arr.base.kind === 'placeArray'));
    if (storageSrc) {
      const lenSlot = this.arraySrcLenSlot(value, ctx, out);
      if (isValueWord(innerElem)) {
        // snapshot the storage array to a [len][elems] memory image (storage is canonical).
        const dst = this.fresh();
        out.push(`let ${dst} := mload(0x40)`);
        const size = this.abiEncFromStorage(t, lenSlot, 0, dst, out);
        out.push(`mstore(0x40, add(${dst}, ${size}))`);
        return { k: 'dynArr', elem: innerElem, ptr: dst, agg: false };
      }
      // a nested-dynamic-leaf array (bytes[]/string[]/T[][]): snapshot to the B4 pointer-headed image.
      const ip = this.fresh();
      out.push(`let ${ip} := ${this.abiDecFromStorageToImage(t, lenSlot, ctx, out)}`);
      return { k: 'dynArr', elem: innerElem, ptr: ip, agg: true };
    }
    if (value.kind === 'arrayValue' && value.arr.base.kind === 'calldataArray') {
      if (!isStaticValueType(innerElem))
        throw new UnsupportedError('a calldata array of non-value elements is not supported');
      const b = ctx.cdArrays.get(value.arr.base.name);
      if (!b) throw new UnsupportedError(`unbound calldata array ${value.arr.base.name}`);
      // solc's calldata->memory conversion at the arg position: decode + VALIDATE each element
      // into a fresh [len][elems] image (the same per-element validation the direct store used).
      const mp = this.fresh();
      out.push(`let ${mp} := mload(0x40)`);
      out.push(`mstore(${mp}, ${b.length})`);
      out.push(`mstore(0x40, add(${mp}, add(0x20, mul(${b.length}, 0x20))))`);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${b.length}) { ${i} := add(${i}, 1) } {`);
      const inner: string[] = [];
      const w = this.fresh();
      inner.push(`let ${w} := calldataload(add(${b.offset}, mul(${i}, 32)))`);
      const guard = this.validateInput(innerElem, w);
      if (guard) inner.push(guard);
      inner.push(`mstore(add(${mp}, add(0x20, mul(${i}, 0x20))), ${w})`);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
      return { k: 'dynArr', elem: innerElem, ptr: mp, agg: false };
    }
    // memory source (a memArray local, new Array<T>(n), a nested image, ...): capture the pointer.
    if (isValueWord(innerElem) || isBytesLike(innerElem) || innerElem.kind === 'array') {
      const p = this.fresh();
      out.push(`let ${p} := ${this.lowerExpr(value, ctx, out)}`);
      return { k: 'dynArr', elem: innerElem, ptr: p, agg: !isValueWord(innerElem) };
    }
    throw new UnsupportedError('a memory array of non-value elements is not supported');
  }

  /** W7B phase 2: perform every storage write of a prepared ctor at `baseSlot`. Pure store
   *  codecs only - all argument evaluation already happened in prepareCtorArgs. */
  private emitPreparedCtorStore(fields: StructField[], items: PreparedFieldArg[], baseSlot: string, out: string[]): void {
    const isConst = /^\d+$/.test(baseSlot);
    const slotAt = (n: number): string =>
      isConst ? String(BigInt(baseSlot) + BigInt(n)) : n === 0 ? baseSlot : `add(${baseSlot}, ${n})`;
    fields.forEach((f, i) => {
      const it = items[i]!;
      switch (it.k) {
        case 'ctor':
          this.emitPreparedCtorStore(it.fields, it.items, slotAt(f.slot), out);
          break;
        case 'dynStruct':
          this.writeDynStructFromMem(f.type as JethType & { kind: 'struct' }, it.ptr, slotAt(f.slot), out);
          break;
        case 'dynArr':
          if (it.agg) this.copyMemAggArrayIntoStorage(it.elem, it.ptr, slotAt(f.slot), out);
          else this.copyMemArrayIntoStorage(it.elem, it.ptr, slotAt(f.slot), out);
          break;
        case 'dynLeafFixed':
          this.storeDynLeafFixedArrayFromMem(f.type as JethType & { kind: 'array' }, it.ptr, slotAt(f.slot), out);
          break;
        case 'lit':
          this.emitPreparedLitStore(it.lit, it.items, slotAt(f.slot), out);
          break;
        case 'staticAgg':
          this.storeStaticAggFromMem(f.type, it.ptr, slotAt(f.slot), out);
          break;
        case 'bytes':
          this.storeDynamic(slotAt(f.slot), it.ref, out);
          break;
        case 'value':
          for (const l of this.storeState(f.type, slotAt(f.slot), f.offset, it.reg)) out.push(l);
          break;
      }
    });
  }

  /** W7B phase 1 for a (possibly nested) fixed-array LITERAL written to storage: evaluate every
   *  element at its source position (value elements frozen to registers; struct / nested-literal
   *  elements recurse into the same two-phase prepare). */
  private prepareLitElems(lit: Expr & { kind: 'arrayLit' }, ctx: LowerCtx, out: string[]): PreparedLitElem[] {
    const elem = lit.elem;
    if (isStaticValueType(elem)) {
      return lit.elements.map((el) => {
        const reg = this.fresh();
        out.push(`let ${reg} := ${this.lowerExpr(el, ctx, out)}`);
        return { k: 'value' as const, reg };
      });
    }
    return lit.elements.map((el) => {
      if (el.kind === 'arrayLit') return { k: 'lit' as const, lit: el, items: this.prepareLitElems(el, ctx, out) };
      if (el.kind === 'structNew')
        return {
          k: 'ctor' as const,
          fields: el.fields,
          items: this.inTransientCapture(() => this.prepareCtorArgs(el.fields, el.args, ctx, out)),
        };
      throw new UnsupportedError(`array-literal element '${el.kind}' is not constructible`);
    });
  }

  /** W7B phase 2 for a prepared fixed-array literal: value elements via arrayElemStore (handles
   *  packing); nested literal / struct elements recurse at baseSlot + k*slotCount(element). */
  private emitPreparedLitStore(
    lit: Expr & { kind: 'arrayLit' },
    items: PreparedLitElem[],
    baseSlot: string,
    out: string[],
  ): void {
    const elem = lit.elem;
    if (isStaticValueType(elem)) {
      items.forEach((it, k) => {
        if (it.k !== 'value') throw new UnsupportedError('prepared literal element kind mismatch');
        this.arrayElemStore(elem, baseSlot, String(k), it.reg, out);
      });
      return;
    }
    const sc = storageSlotCount(elem);
    const isConst = /^\d+$/.test(baseSlot);
    const slotAt = (n: number): string =>
      isConst ? String(BigInt(baseSlot) + BigInt(n)) : n === 0 ? baseSlot : `add(${baseSlot}, ${n})`;
    items.forEach((it, k) => {
      const es = slotAt(k * sc);
      if (it.k === 'lit') this.emitPreparedLitStore(it.lit, it.items, es, out);
      else if (it.k === 'ctor') this.emitPreparedCtorStore(it.fields, it.items, es, out);
      else throw new UnsupportedError('prepared literal element kind mismatch');
    });
  }

  /** Allocate a memory image for a constructed STATIC struct (G9) and return its pointer.
   *  Layout is ABI-unpacked (one word per leaf), so the image doubles as the ABI return blob. */
  /** Materialize a static struct / fixed-array aggregate value to a memory image pointer (used
   *  by an aggregate ternary branch): a constructed value allocates fresh; a storage source is
   *  COPIED into a fresh image; a memory-aggregate local aliases its pointer. */
  private aggToMemPtr(e: Expr, ctx: LowerCtx, out: string[]): string {
    if (e.kind === 'structNew' || e.kind === 'arrayLit') return this.allocAggToMem(e, ctx, out);
    if (e.kind === 'memAggregate' || e.kind === 'ternary') return this.lowerExpr(e, ctx, out); // a nested aggregate ternary recurses (materialize + select)
    if (e.kind === 'memDynStructValue') return this.ctxLookup(ctx, e.local); // B4: the dyn-struct local's image pointer; a nested static-aggregate field is INLINE at headWord (aggFieldRead adds the offset)
    if (e.kind === 'structValue') return this.allocAggFromStorage(e.type, String(e.baseSlot), out);
    if (e.kind === 'mapStorageValue')
      return this.allocAggFromStorage(e.type, this.mappingSlot(e.baseSlot, e.keys, ctx, out), out);
    if (e.kind === 'structArrayElem')
      return this.allocAggFromStorage(e.type, this.structArrayElemSlot(e.arr, e.index, ctx, out), out);
    if (e.kind === 'placeRead') return this.allocAggFromStorage(e.type, this.lowerPlace(e.path, ctx, out).slot, out);
    if (e.kind === 'arrayValue' && e.arr.base.kind === 'fixedArray')
      return this.allocAggFromStorage(e.type, String(e.arr.base.baseSlot), out);
    if (e.kind === 'cdAggregateValue') return this.allocAggFromCalldata(e.param, e.type, ctx, out);
    if (e.kind === 'cdPlaceReadAgg') {
      // S4: a WHOLE STATIC-AGGREGATE LEAF of a fully-static outer calldata param (n.inner, n.arr,
      // n.inner.d). Fold the place to the leaf's calldata byte offset, then COPY it into a fresh
      // memory image via the SAME validating codec the whole-param / struct-array-element copies use
      // (allocAggFromCalldataBase -> abiEncFromCd with validate=true): each constituent static word is
      // loaded THROUGH validateInput (a dirty bool/address word EMPTY-reverts, matching solc's lazy
      // validate-on-access). The pointer is byte-identical to a memory-local static-aggregate image.
      const off = this.lowerCdPlace(e.place, ctx, out);
      return this.allocAggFromCalldataBase(e.type, off, out);
    }
    if (e.kind === 'arrayGet') {
      // Cat B: a STATIC STRUCT element of a memory P[] (xs[i]). lowerArrayGet returns the element's
      // ABSOLUTE image pointer (the pointer-headed slot), which IS a struct image - so aggFieldRead
      // (xs[i].a) / passing xs[i] / encoding it / aliasing it all consume it directly. Freeze it.
      const p = this.fresh();
      out.push(`let ${p} := ${this.lowerArrayGet(e, ctx, out)}`);
      return p;
    }
    if (e.kind === 'call') {
      const p = this.fresh();
      out.push(`let ${p} := ${this.lowerExpr(e, ctx, out)}`);
      return p;
    }
    if (e.kind === 'aggFieldRead') {
      // a whole STATIC AGGREGATE field of a memory-array struct element (xs[i].pre / xs[i].q): the
      // sub-image pointer into the element image. Freeze it (consumers read multiple words from it).
      const r = this.fresh();
      out.push(`let ${r} := ${this.aggFieldPtr(e.base, e.wordOffset, e.runSteps, ctx, out)}`);
      return r;
    }
    if (e.kind === 'memDynNestedField' && e.deref && e.type.kind === 'struct' && isDynamicType(e.type)) {
      // W5A: the deref-chain BASE of a static-aggregate chain rooted at a NESTED dyn-struct reference
      // (v.t.inner / v.t.fa[j]): deref the chain, then the final head word holds the owning image's
      // absolute pointer. lowerDynamic freezes it into a fresh let (aggFieldPtr adds the inline offset).
      const ref = this.lowerDynamic(e, ctx, out);
      if (ref.src !== 'memory') throw new UnsupportedError('expected a memory nested dyn-struct image reference');
      return ref.ptr;
    }
    if (e.kind === 'cdStructArrayElem' && isStaticType(e.type)) {
      // abi.encode(xs[i].items[j]) where D is a STATIC struct: the element is contiguous in calldata
      // (no offset table) and its calldata layout IS the ABI-unpacked image. Resolve the element base
      // (Panic 0x32 on OOB i/j, the array payload already validated readable), then decode + VALIDATE it
      // into a fresh image via abiEncFromCd. cap = empty-revert (abi.encode's calldata->memory decode);
      // a static struct has no inner length, so the only faults (truncated/OOB) EMPTY-revert regardless.
      const eb = this.cdArrayElemBase(e.arr, e.index, e.type, ctx, out);
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      const size = this.abiEncFromCd(e.type, eb, ptr, true, out, true);
      out.push(`mstore(0x40, add(${ptr}, ${size}))`);
      return ptr;
    }
    if (e.kind === 'abiDecode') {
      // abi.decode(b, P).x / an @external library delegatecall result L.mk(a).x: lowerAbiDecode produces a
      // fresh decoded image (the flat ABI image for a static struct), the same pointer aggFieldRead reads
      // the field word from. Freeze it (the consumer may read multiple words).
      const p = this.fresh();
      out.push(`let ${p} := ${this.lowerAbiDecode(e.data, [e.type], ctx, out)[0]!}`);
      return p;
    }
    throw new UnsupportedError(`cannot materialize aggregate ternary branch '${e.kind}'`);
  }

  private allocAggToMem(value: Expr & { kind: 'structNew' | 'arrayLit' }, ctx: LowerCtx, out: string[]): string {
    const words = abiHeadWords(value.type);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${words * 32}))`);
    this.writeAggToMem(value, ptr, 0, ctx, out);
    return ptr;
  }

  /** Build JETH's nested-VALUE-array memory image (the representation abiEncFromMem reads) for a
   *  type `t` whose leaves are all value types but at least one nesting level is DYNAMIC (so it is
   *  not a pure static aggregate). Returns the image pointer.
   *   - DYNAMIC array `T[]`: allocate [len] then, per element, an inline static block (static element)
   *     or an absolute pointer to the element's own freshly-built image (dynamic element).
   *   - FIXED array `Arr<T,N>` with a DYNAMIC element: N absolute-pointer words (no length header).
   *   - a STATIC array element (Arr<value,N> / Arr<Arr<value,N>,M>) is built inline via allocAggToMem.
   *  `lit` is the matching array literal (its element count drives a dynamic length). FREEZE each
   *  inner image FIRST (its allocation bumps the free pointer) before claiming the parent block,
   *  mirroring the value-element arrayLit case. */
  private buildNestedMemArrayLit(lit: Expr & { kind: 'arrayLit' }, ctx: LowerCtx, out: string[]): string {
    const t = lit.type as JethType & { kind: 'array' };
    const elem = t.element as JethType;
    // Materialize each element FIRST (left-to-right), freezing its register, so any inner allocation
    // bumps the free pointer before we claim this level's header.
    const elemVals = lit.elements.map((el) => {
      if (isInlineValueWordElem(elem)) {
        // a static/funcref VALUE element (value word, or a static/funcref fixed VALUE sub-array): build its
        // inline image and copy it into place below; here just capture its source.
        return null; // handled inline in the static-element copy loop
      }
      // a dynamic element OR a Cat-B static-struct element (pointer-headed): build the per-element
      // image, capture its absolute pointer.
      const p = this.fresh();
      out.push(`let ${p} := ${this.buildNestedMemArrayValue(el as Expr, ctx, out)}`);
      return p;
    });
    if (t.length === undefined) {
      // DYNAMIC outer.
      if (isInlineValueWordElem(elem)) {
        // static element: [len] + inline element blocks (one abiHeadWords(elem) block each).
        const ew = abiHeadWords(elem);
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(0x40)`);
        out.push(`mstore(${ptr}, ${lit.elements.length})`);
        out.push(`mstore(0x40, add(${ptr}, ${(1 + lit.elements.length * ew) * 32}))`);
        lit.elements.forEach((el, k) => this.writeStaticElemBlock(elem, el as Expr, ptr, 1 + k * ew, ctx, out));
        return ptr;
      }
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      out.push(`mstore(${ptr}, ${lit.elements.length})`);
      out.push(`mstore(0x40, add(${ptr}, ${(1 + lit.elements.length) * 32}))`);
      elemVals.forEach((p, k) => out.push(`mstore(add(${ptr}, ${(1 + k) * 32}), ${p})`));
      return ptr;
    }
    // FIXED outer with a DYNAMIC element: N absolute-pointer words, no length header.
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${t.length * 32}))`);
    elemVals.forEach((p, k) => out.push(`mstore(add(${ptr}, ${k * 32}), ${p})`));
    return ptr;
  }

  /** Write a STATIC array element (a value word, or a static fixed sub-array literal) inline into a
   *  nested-array image at word `wordBase`. A value element mstores its lowered word; a static
   *  aggregate literal (Arr<value,N> as an element of a dynamic outer) recurses via writeAggToMem. */
  private writeStaticElemBlock(elem: JethType, el: Expr, ptr: string, wordBase: number, ctx: LowerCtx, out: string[]): void {
    const at = wordBase === 0 ? ptr : `add(${ptr}, ${wordBase * 32})`;
    // isValueWord: a value type OR a funcref (FIX nested funcref: a funcref LEAF element - e.g. of a
    // ((x)=>R)[] inner - mstores its id word, exactly like a uint256 leaf).
    if (isValueWord(elem)) {
      out.push(`mstore(${at}, ${this.lowerExpr(el, ctx, out)})`);
      return;
    }
    this.writeAggToMem(el, ptr, wordBase, ctx, out);
  }

  /** Build a nested-value-array ELEMENT image (recursion helper for buildNestedMemArrayLit). A static
   *  element (value or static fixed sub-array) uses allocAggToMem; a nested DYNAMIC sub-array literal
   *  recurses into buildNestedMemArrayLit. Returns the element image pointer. */
  private buildNestedMemArrayValue(el: Expr, ctx: LowerCtx, out: string[]): string {
    // Residual B2: a bytes/string element of a bytes[]/string[] literal (a bytesLit / bytes(...) cast /
    // template literal / another memory bytes value). Materialize it to a fresh [len][data] memory blob;
    // the element word holds that absolute pointer (mirrors a dynamic-array element).
    if (isBytesLike(el.type)) {
      const { mp } = this.toMemory(this.lowerDynamic(el, ctx, out), out);
      // toMemory returns the SOURCE pointer for an already-in-memory value; an array literal must own a
      // distinct blob per element, so a fresh literal/cast already allocated one. A pure alias is the rare
      // case; freeze the pointer (reference semantics match solc - an array of aliases would share a blob,
      // but a bytesLit/cast/template always allocates fresh, the only sources this scope accepts).
      return mp;
    }
    if (el.kind === 'arrayLit') {
      // a static/funcref VALUE sub-array (Arr<u256,N>, and FIX: Arr<(x)=>R,N>) is built INLINE; a
      // static-struct-leaf fixed array (Batch A: Arr<P,N> as an element of Arr<P,N>[] / Arr<Arr<P,N>,M>)
      // is POINTER-HEADED, so build its image via the nested codec (N pointer words, no [len] header)
      // exactly like a dynamic inner.
      if (isInlineValueWordElem(el.type)) return this.allocAggToMem(el, ctx, out);
      return this.buildNestedMemArrayLit(el, ctx, out);
    }
    if (el.kind === 'newArray') return this.lowerExpr(el, ctx, out);
    // Residual B3: a DYNAMIC-field struct element built by a constructor `P(...)` (P[] literal): the
    // element word holds an absolute pointer to a pointer-headed dyn-struct image (value fields inline,
    // bytes/string + dynamic value-array fields a head pointer), the same image buildDynStructLocal uses.
    if (el.kind === 'structNew' && el.type.kind === 'struct' && isDynamicType(el.type)) {
      return this.allocDynStructToMem(el as Expr & { kind: 'structNew' }, ctx, out);
    }
    // Cat B: a STATIC-struct element of a P[] literal is now POINTER-HEADED. A constructor P(...)
    // allocates a fresh per-element image; a reference source (another element xs[j], a struct local,
    // a storage/calldata struct) is materialized via aggToMemPtr (a memory ref ALIASES its image
    // pointer, a storage/calldata source COPIES into a fresh image) - reference semantics matching
    // solc's array literal of struct references.
    if (el.type.kind === 'struct' && isStaticType(el.type)) {
      if (el.kind === 'structNew') return this.allocAggToMem(el as Expr & { kind: 'structNew' }, ctx, out);
      return this.aggToMemPtr(el, ctx, out);
    }
    // W5C (family-wide): a DYNAMIC-field struct VALUE element of a P[] literal ([a, b] where a/b are
    // P memory locals / storage / calldata structs): a memory source ALIASES its pointer-headed image
    // (reference semantics, same as xs[i] = a); a storage/calldata source COPIES into a fresh image.
    // Previously fell to lowerExpr and threw JETH900 ('memDynStructValue in a non-reference context').
    if (el.type.kind === 'struct' && isDynamicType(el.type)) {
      return this.buildDynStructLocal(el.type, el, ctx, out);
    }
    // a memory-array expression (alias / element of another nested array): its register IS the pointer.
    return this.lowerExpr(el, ctx, out);
  }

  /** Zero-initialize a nested-value-array memory image for `new Array<E>(n)` where E is itself an
   *  array (the outer is dynamic, length n at runtime). solc ACTIVELY zero-inits each outer element
   *  to a POINTER to a fresh EMPTY inner image. Returns the outer image pointer. The inner empty
   *  image is a single zero word ([len=0] for a dynamic inner; for a STATIC inner element, solc still
   *  allocates an all-zero block of abiHeadWords words). */
  private zeroInitNestedMemArray(outer: JethType & { kind: 'array' }, nExpr: string, ctx: LowerCtx, out: string[]): string {
    const elem = outer.element as JethType;
    const n = this.fresh();
    out.push(`let ${n} := ${nExpr}`);
    out.push(`if gt(${n}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
    if (isInlineValueWordElem(elem)) {
      // a static/funcref VALUE element (e.g. Arr<u256,2>, Arr<(x)=>R,2>): [len] + n inline zero blocks.
      // calldatacopy zeros (a zero funcref id Panics 0x51 on call, matching solc's zero-init element).
      const ew = abiHeadWords(elem);
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      out.push(`mstore(${ptr}, ${n})`);
      out.push(`calldatacopy(add(${ptr}, 0x20), calldatasize(), mul(${n}, ${ew * 32}))`);
      out.push(`mstore(0x40, add(${ptr}, mul(add(mul(${n}, ${ew}), 1), 0x20)))`);
      return ptr;
    }
    // a DYNAMIC element: build the outer [len][ptr...] then, per element, an empty inner image. solc
    // emits one shared empty inner per element via a loop. Each inner empty image is built by
    // zeroInitInnerEmpty (recursively zero for deeper nesting).
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, ${n})`);
    out.push(`mstore(0x40, add(${ptr}, mul(add(${n}, 1), 0x20)))`);
    const i = this.fresh();
    out.push(`for { let ${i} := 0 } lt(${i}, ${n}) { ${i} := add(${i}, 1) } {`);
    const inner: string[] = [];
    const ip = this.fresh();
    inner.push(`let ${ip} := ${this.emptyInnerImage(elem, inner)}`);
    inner.push(`mstore(add(${ptr}, mul(add(${i}, 1), 0x20)), ${ip})`);
    for (const l of inner) out.push('  ' + l);
    out.push('}');
    return ptr;
  }

  /** Build a fresh EMPTY image for a (dynamic) inner element of a zero-initialized nested array:
   *  a single [len=0] word. (A deeper dynamic inner is still empty at length 0, so one zero word
   *  suffices; abiEncFromMem reads len=0 and emits no tail.) A bytes/string element (Residual B2)
   *  uses the SAME [len=0] image - an empty blob - so this serves both inner-array and bytes elements.
   *  Residual B3: a DYNAMIC-field struct element (P with bytes/string/dyn-array fields) zero-inits to a
   *  full pointer-headed dyn-struct image: value fields are 0, each dynamic field's head word points to
   *  an empty [len=0] sentinel (a safe read; indexing it Panics 0x32 - matching solc's `new P[](n)`). */
  private emptyInnerImage(t: JethType, out: string[]): string {
    if (t.kind === 'struct' && isDynamicType(t)) return this.emptyDynStructImage(t, out);
    // Cat B: a STATIC-struct element of `new P[](n)` is POINTER-HEADED; each slot points to a fresh
    // ALL-ZERO element image of abiHeadWords(P) words (every leaf default-initialized to 0), matching
    // solc's zero element. calldatacopy from an out-of-range source zeros the block.
    if (t.kind === 'struct' && isStaticType(t)) {
      const hw = abiHeadWords(t);
      const p = this.fresh();
      out.push(`let ${p} := mload(0x40)`);
      out.push(`calldatacopy(${p}, calldatasize(), ${hw * 32})`);
      out.push(`mstore(0x40, add(${p}, ${hw * 32}))`);
      return p;
    }
    const p = this.fresh();
    out.push(`let ${p} := mload(0x40)`);
    out.push(`mstore(${p}, 0)`);
    out.push(`mstore(0x40, add(${p}, 0x20))`);
    return p;
  }

  /** W5C: build a fresh ZERO image for a FIXED-outer dynamic-element array (Arr<string,N>/Arr<bytes,N>/
   *  Arr<u256[],N>, and nested Arr<Arr<string,M>,N>): N absolute-pointer words (no [len] header), each
   *  pointing to a fresh empty element image ([len=0] for a bytes/string/dynamic-array element; a
   *  recursive M-pointer image for a fixed dyn-leaf sub-array). ctx-free twin of zeroImageFor's
   *  fixed-outer branch, usable from emptyDynStructImage. */
  private emptyFixedDynImage(t: JethType & { kind: 'array' }, out: string[]): string {
    const p = this.fresh();
    out.push(`let ${p} := mload(0x40)`);
    out.push(`mstore(0x40, add(${p}, ${t.length! * 32}))`);
    for (let k = 0; k < t.length!; k++) {
      const el = t.element;
      const ip =
        el.kind === 'array' && el.length !== undefined
          ? this.emptyFixedDynImage(el, out)
          : this.emptyInnerImage(el, out);
      out.push(`mstore(add(${p}, ${k * 32}), ${ip})`);
    }
    return p;
  }

  /** Build a fresh zero-value dyn-struct image (Residual B3 element of `new Array<P>(n)`): one head
   *  word per field (value fields = 0; bytes/string + dynamic value-array fields a pointer to a fresh
   *  empty [len=0] sentinel blob). Byte-identical to solc's zero element image. */
  private emptyDynStructImage(struct: JethType & { kind: 'struct' }, out: string[]): string {
    const headWords = tupleHeadWords(struct);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${headWords * 32}))`);
    let hw = 0;
    for (const f of struct.fields) {
      const at = hw === 0 ? ptr : `add(${ptr}, ${hw * 32})`;
      if (f.type.kind === 'array' && f.type.length !== undefined && isDynamicType(f.type)) {
        // W5C: a FIXED-outer DYNAMIC-element field (Arr<string,N>): the zero value is a full N-pointer
        // fixed image, each pointer -> a fresh empty element image (NOT a [len=0] sentinel - the fixed
        // image has no length header, and element reads deref the N pointer words).
        out.push(`mstore(${at}, ${this.emptyFixedDynImage(f.type, out)})`);
        hw += 1;
      } else if (isDynamicType(f.type)) {
        // a bytes/string or dynamic value-array field: head word -> a fresh empty [len=0] sentinel.
        const blob = this.fresh();
        out.push(`let ${blob} := mload(0x40)`);
        out.push(`mstore(${blob}, 0)`);
        out.push(`mstore(0x40, add(${blob}, 0x20))`);
        out.push(`mstore(${at}, ${blob})`);
        hw += 1;
      } else {
        // a value field: one (or more, for a static aggregate - excluded by isDynStructLeaf) zero head word.
        for (let k = 0; k < abiHeadWords(f.type); k++) out.push(`mstore(${hw + k === 0 ? ptr : `add(${ptr}, ${(hw + k) * 32})`}, 0)`);
        hw += abiHeadWords(f.type);
      }
    }
    return ptr;
  }

  /** Allocate a fresh memory image for a static aggregate and COPY it from a STORAGE source
   *  (G9: `let p: P = this.s`). abiEncFromStorage transcodes the packed storage into the
   *  ABI-unpacked image (one word per leaf), which is exactly the memAggregate layout. */
  private allocAggFromStorage(type: JethType, slot: string, out: string[]): string {
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${abiHeadWords(type) * 32}))`);
    this.abiEncFromStorage(type, slot, 0, ptr, out);
    return ptr;
  }

  /** Allocate a fresh memory image for a static aggregate and COPY it from a CALLDATA param
   *  (G9: `let q: P = calldataStructParam`). The param data is inline at its head word;
   *  abiEncFromCd decodes it (validating dirty narrow fields like solc) into the image. */
  private allocAggFromCalldata(
    param: string,
    type: JethType,
    ctx: LowerCtx,
    out: string[],
    bindContext = false,
  ): string {
    const ph = ctx.cdParamHead.get(param);
    if (!ph) throw new UnsupportedError(`unbound struct-copy param ${param}`);
    return this.allocAggFromCalldataBase(type, String(ph.head), out, bindContext);
  }

  /** Allocate a fresh memory image for a static aggregate and COPY it from a precomputed CALLDATA
   *  base (G9: `let p: P = ps[i]`, a calldata struct-array element). The same abiEncFromCd transcode
   *  the whole-param copy uses (validating dirty narrow fields like solc), applied at the element's
   *  contiguous calldata head. */
  private allocAggFromCalldataBase(type: JethType, base: string, out: string[], bindContext = false): string {
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${abiHeadWords(type) * 32}))`);
    // W6C: in the BIND context (`const b: Arr<u8,3> = a` / an internal-call arg) a BARE VALUE-LEAF
    // fixed array is a raw calldatacopy in solc: non-enum leaves are MASKED (never revert - the
    // memory read masks again), enum words copy RAW and Panic 0x21 lazily at the element read.
    // In the ENCODE context (abi.encode(a) / event data via aggToMemPtr) solc reads the elements
    // from CALLDATA and VALIDATES each (EMPTY revert - verified vs 0.8.35), so keep validate=true.
    // A STRUCT (even one holding a fixed enum-array field) always keeps the eager per-leaf
    // VALIDATION (EMPTY revert), solc's struct convert-to-memory flavor.
    const rawCopy = bindContext && isValueLeafArray(type);
    this.abiEncFromCd(type, base, ptr, !rawCopy, out, false, rawCopy);
    return ptr;
  }

  /** Allocate a memory image for a DYNAMIC-field struct local from a constructor `D(...)`.
   *  Layout = one head word per field: value fields inline, bytes/string fields a pointer to
   *  a freshly-materialized [len][data] blob. This coincides with the ABI tuple head layout,
   *  so `return d` reuses encodeDynStructReturn through a 'mem' TupleSrc. Scoped to value +
   *  bytes/string fields (no static-aggregate or nested-struct fields), so each field is one
   *  head word and field i sits at word i. The head is allocated first (args materialize their
   *  blobs above it); constructor args evaluate left-to-right, matching solc. */
  private allocDynStructToMem(value: Expr & { kind: 'structNew' }, ctx: LowerCtx, out: string[]): string {
    const struct = value.type as JethType & { kind: 'struct' };
    const headWords = tupleHeadWords(struct);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${headWords * 32}))`);
    let hw = 0;
    struct.fields.forEach((f, i) => {
      const at = hw === 0 ? ptr : `add(${ptr}, ${hw * 32})`;
      if (isBytesLike(f.type)) {
        const { mp } = this.toMemory(this.lowerDynamic(value.args[i]!, ctx, out), out);
        out.push(`mstore(${at}, ${mp})`);
        hw += 1;
      } else if (f.type.kind === 'array' && f.type.length === undefined && isStaticValueType(f.type.element)) {
        // a dynamic value-array field: materialize the arg to a [len][elems] memory pointer, store it.
        out.push(`mstore(${at}, ${this.aggArgToMemPtr(value.args[i]!, ctx, out)})`);
        hw += 1;
      } else if (f.type.kind === 'array' && f.type.length === undefined) {
        // Cat C: a NESTED-DYNAMIC-LEAF array field (bytes[]/string[]/T[][]). Build the B4 pointer-headed
        // image of the arg (an array literal / new Array<E>(n) / a memory aggregate-array source), store
        // its absolute pointer in the head word - the same image abiEncFromMem/read/decode consume.
        out.push(`mstore(${at}, ${this.nestedMemImagePtr(value.args[i]!, ctx, out)})`);
        hw += 1;
      } else if (
        f.type.kind === 'array' &&
        f.type.length !== undefined &&
        (isDynLeafFixedArray(f.type) || isDynStructFixedLeafArray(f.type))
      ) {
        // W5C: a FIXED-outer DYNAMIC-element field (Arr<string,N>/Arr<bytes,N>/Arr<u256[],N>), and Lift #4:
        // a FIXED-outer DYNAMIC-STRUCT field (Arr<In,N>): ONE head word holding an absolute pointer to the
        // N-pointer-word fixed image (no [len] header). aggArgToMemPtr materializes the arg (a literal via
        // buildNestedMemArrayLit -> per-element allocDynStructToMem; a memory local/param ALIASES; a
        // storage/calldata source deep-copies via abiDec*ToImage) - the same image the read/encode/store
        // paths consume. tupleHeadWords counts the field as 1 (dynamic). NOTE: this MUST precede the
        // static-aggregate inline branch below, which would otherwise inline abiHeadWords(Arr<In,N>)=N*hw
        // words (a MISCOMPILE: the field is 1 pointer word in the tuple head, not N inline).
        out.push(`mstore(${at}, ${this.aggArgToMemPtr(value.args[i]!, ctx, out)})`);
        hw += 1;
      } else if (f.type.kind === 'struct' && isDynamicType(f.type)) {
        // a NESTED DYNAMIC struct field: its head word is a POINTER to the nested struct's own
        // pointer-headed image (1 head word, matching tupleHeadWords/memDynStructField). W6A: route
        // EVERY source through buildDynStructLocal - an inline constructor builds a fresh image
        // (allocDynStructToMem, as before); a MEMORY source (local / param / nested field / element /
        // call / ternary) stores its existing image POINTER (Solidity memory-reference semantics -
        // previously the analyzer desugared this into a field-read COPY, a confirmed miscompile);
        // a STORAGE / CALLDATA source deep-copies into a fresh image (solc's conversion is a copy).
        // The dyn-struct encoders read it back via nestedTupleSrc (the `mem` branch follows this
        // pointer).
        const narg = value.args[i]!;
        out.push(`mstore(${at}, ${this.buildDynStructLocal(f.type, narg, ctx, out)})`);
        hw += 1;
      } else if (f.type.kind === 'struct' || (f.type.kind === 'array' && f.type.length !== undefined)) {
        // B(1): a NESTED STATIC AGGREGATE field (nested static struct / fixed array Arr<T,N>). Materialize
        // the arg to its flat static image, then copy its abiHeadWords leaf words INLINE at word offset hw
        // (the tuple-head layout solc uses). The single-word else below would write ONLY the first leaf
        // while hw advances by abiHeadWords, corrupting every later field of a multi-word aggregate.
        // W6A: the inline copy is only sound for a copy-by-value source or a transient consumer.
        // W7A: inside a two-phase encode's phase 1 a live-memory source records a capture patch
        // (a late re-copy through the same pointer, after every sibling component's side effects).
        this.assertInlineAggCaptureSound(value.args[i]!, `constructed struct field '${f.name}'`, f.type);
        const fsrc = this.aggArgToMemPtr(value.args[i]!, ctx, out);
        const fw = abiHeadWords(f.type);
        for (let k = 0; k < fw; k++) {
          out.push(`mstore(add(${ptr}, ${(hw + k) * 32}), mload(add(${fsrc}, ${k * 32})))`);
        }
        this.recordCapturePatch(value.args[i]!, hw === 0 ? ptr : `add(${ptr}, ${hw * 32})`, fsrc, fw * 32);
        hw += fw;
      } else {
        out.push(`mstore(${at}, ${this.lowerExpr(value.args[i]!, ctx, out)})`);
        hw += abiHeadWords(f.type);
      }
    });
    return ptr;
  }

  /** Build a DYNAMIC-field struct memory local's pointer-headed image from any supported
   *  source: a constructor (fresh), a storage struct (COPY), a calldata struct param (decode
   *  + validate into a fresh image), or another dynamic-struct memory local (ALIAS = pointer
   *  copy, matching Solidity memory references). Returns the head pointer. */
  private buildDynStructLocal(struct: JethType & { kind: 'struct' }, init: Expr, ctx: LowerCtx, out: string[]): string {
    if (init.kind === 'structNew') return this.allocDynStructToMem(init, ctx, out);
    if (init.kind === 'memDynStructValue') return this.ctxLookup(ctx, init.local); // alias
    if (init.kind === 'call') return this.lowerExpr(init, ctx, out); // a struct-returning internal call yields the pointer-headed image pointer (ALIAS, like solc memory references)
    if (init.kind === 'ternary') return this.lowerExpr(init, ctx, out); // selects an already-built branch image pointer
    if (init.kind === 'cdDynStructValue') return this.buildDynStructFromCalldata(struct, init, ctx, out);
    // a DYNAMIC-field struct ELEMENT of a calldata struct array (let d: D = ds[i]): copy the
    // element's calldata tuple into a fresh pointer-headed image (the same materializer the
    // whole-param path uses, at the element's offset-located calldata base).
    if (init.kind === 'cdStructArrayElem') return this.buildDynStructFromCalldata(struct, init, ctx, out);
    // abi.decode(b, D) into a dynamic-field struct: lowerAbiDecode routes the single struct component to
    // buildDynStructFromMemBlob, which builds the same pointer-headed image (memory-decode revert semantics).
    if (init.kind === 'abiDecode') return this.lowerAbiDecode(init.data, [init.type], ctx, out)[0]!;
    // a DYNAMIC-field struct ELEMENT of a MEMORY struct array (let d: D = ds[i], ds: D[]): D[] is
    // POINTER-HEADED, so aggToMemPtr returns the element slot's absolute pointer VALUE - binding d
    // ALIASES the element image (no copy). Mutating d writes through to ds[i]; re-pointing ds[i] = D(...)
    // rewrites the slot pointer and leaves d on the old image, byte-identical to solc memory references.
    if (init.kind === 'arrayGet') return this.aggToMemPtr(init, ctx, out);
    // a whole NESTED DYNAMIC struct FIELD of a dyn-struct memory local (let t: T = v.t, g(v.t), v.t.u):
    // the field's head word holds an absolute pointer to the nested image (the OR6 / Edge-A layout), so
    // lowerDynamic yields that pointer - binding/passing it ALIASES the image (solc memory references),
    // exactly like the memDynStructValue / arrayGet / call cases above.
    if (init.kind === 'memDynField' || init.kind === 'memDynNestedField') {
      const ref = this.lowerDynamic(init, ctx, out);
      if (ref.src !== 'memory') throw new UnsupportedError('expected a memory dynamic-struct reference');
      return ref.ptr;
    }
    // a storage struct source (structValue / mapStorageValue / structArrayElem / placeRead).
    return this.buildDynStructFromStorage(struct, this.structSrcSlot(init, ctx, out), ctx, out);
  }

  /** Copy a storage dynamic-field struct at `baseSlot` into a fresh memory image: value fields
   *  are read (packed-aware) and stored inline; bytes/string fields are copied to a memory blob
   *  whose pointer is stored in the head word. Scoped to value + bytes/string fields. */
  private buildDynStructFromStorage(
    struct: JethType & { kind: 'struct' },
    baseSlot: string,
    ctx: LowerCtx,
    out: string[],
  ): string {
    const headWords = tupleHeadWords(struct);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${headWords * 32}))`);
    const isConst = /^\d+$/.test(baseSlot);
    const slotAt = (n: number): string =>
      isConst ? String(BigInt(baseSlot) + BigInt(n)) : n === 0 ? baseSlot : `add(${baseSlot}, ${n})`;
    let hw = 0;
    for (const f of struct.fields) {
      const at = hw === 0 ? ptr : `add(${ptr}, ${hw * 32})`;
      if (isBytesLike(f.type)) {
        const { mp } = this.toMemory({ src: 'storage', slot: slotAt(f.slot) }, out);
        out.push(`mstore(${at}, ${mp})`);
        hw += 1;
      } else if (f.type.kind === 'array' && f.type.length === undefined && isStaticValueType(f.type.element)) {
        // a dynamic value-array field: copy the storage array (length slot = f's slot) to a fresh
        // [len][elems] memory image (storage is canonical, no masking needed); store the pointer.
        const dst = this.fresh();
        out.push(`let ${dst} := mload(0x40)`);
        const size = this.abiEncFromStorage(f.type, slotAt(f.slot), 0, dst, out);
        out.push(`mstore(0x40, add(${dst}, ${size}))`);
        out.push(`mstore(${at}, ${dst})`);
        hw += 1;
      } else if (f.type.kind === 'array' && f.type.length === undefined) {
        // a NESTED-DYNAMIC-LEAF array field (bytes[]/string[]/T[][]): build its pointer-headed B4 image
        // directly from storage (the [len] + per-element absolute-pointer table abiDecFromStorageToImage
        // produces for a dynamic-element array), then store that absolute pointer in the head word - the
        // same image shape a dynamic value-array field stores. The dyn-struct ABI encoders read it back
        // as a pointer-headed leaf-array field; byte-identical to solc (verified on the harness).
        const dst = this.fresh();
        out.push(`let ${dst} := ${this.abiDecFromStorageToImage(f.type, slotAt(f.slot), ctx, out)}`);
        out.push(`mstore(${at}, ${dst})`);
        hw += 1;
      } else if (f.type.kind === 'array' && f.type.length !== undefined && isDynamicType(f.type)) {
        // W5C: a FIXED-outer DYNAMIC-element field (Arr<string,N>): build its N-pointer fixed image
        // directly from the field's N consecutive storage slots (abiDecFromStorageToImage's fixed-array
        // branch), then store the image's absolute pointer in the ONE head word. The static-aggregate
        // branch below would inline-flatten it (wrong: this field is pointer-headed, 1 head word).
        const dst = this.fresh();
        out.push(`let ${dst} := ${this.abiDecFromStorageToImage(f.type, slotAt(f.slot), ctx, out)}`);
        out.push(`mstore(${at}, ${dst})`);
        hw += 1;
      } else if (f.type.kind === 'struct' && isDynamicType(f.type)) {
        // a nested DYNAMIC struct field (T with a bytes/string/dyn-array/nested-dyn member): its head word
        // holds an absolute POINTER to a recursively-built nested pointer-headed image (from the field's
        // sub-slot), NOT an inline flatten. tupleHeadWords counts it as 1. (The static-aggregate branch
        // below would mis-flatten it inline and over-advance hw, corrupting the head/tail offsets - a
        // silent miscompile of abi.encode(this.w) / passing this.w onward.)
        const dst = this.buildDynStructFromStorage(f.type, slotAt(f.slot), ctx, out);
        out.push(`mstore(${at}, ${dst})`);
        hw += 1;
      } else if (f.type.kind === 'struct' || (f.type.kind === 'array' && f.type.length !== undefined)) {
        // a nested STATIC aggregate field (struct / fixed-array): flatten ALL its leaves into the head
        // (one ABI head word per leaf) directly from storage, via the same storage->ABI transcoder the
        // return/event encoders use. The plain loadState below writes only the FIRST word (and, for a
        // packed multi-field struct, the wrong packed word) while advancing the cursor by abiHeadWords,
        // corrupting the encoding of any aggregate spanning >=2 head words (event topic AND data).
        this.abiEncFromStorage(f.type, slotAt(f.slot), 0, at, out);
        hw += abiHeadWords(f.type);
      } else {
        out.push(`mstore(${at}, ${this.loadState(f.type, slotAt(f.slot), f.offset)})`);
        hw += abiHeadWords(f.type);
      }
    }
    return ptr;
  }

  /** Decode a calldata dynamic-field struct param into a fresh memory image: value fields are
   *  read + VALIDATED inline (encodeStaticInline 'cd'), bytes/string fields are calldatacopied
   *  to a memory blob whose pointer is stored in the head word. Matches solc's copy-to-memory. */
  private buildDynStructFromCalldata(
    struct: JethType & { kind: 'struct' },
    init: Expr,
    ctx: LowerCtx,
    out: string[],
    // CONTEXT SPLIT (probe-verified vs solc 0.8.35): the oversized-inner-LENGTH cap of a dynamic field
    // (string/bytes length, dynamic value-array count, leaf-array outer/inner count) is FLAVOR-selected
    // by the consumer of this materialized image:
    //   - the BIND context (`let m: R = p` / `let d: D = ds[i]`, a calldata->MEMORY DEEP COPY) hits
    //     solc's memory ALLOCATION guard -> Panic 0x41 (emptyCap = FALSE, the default).
    //   - the abi.encode / emit / error RE-ENCODE context (tupleSrc materializes an array-field struct
    //     into this image, then re-encodes it) is an ABI-decode-failure flavor -> EMPTY revert
    //     (emptyCap = TRUE), byte-identical to solc re-encoding a malformed calldata aggregate.
    // A TRUNCATED / OOB source (offset or payload past calldatasize) ALWAYS empty-reverts in BOTH
    // flavors (the payload-fits guards keep revert(0, 0)), matching solc.
    emptyCap = false,
  ): string {
    // Resolve the calldata tuple-start DIRECTLY (do NOT route through tupleSrc: tupleSrc now materializes
    // an array-field calldata struct to memory by calling THIS function, which would recurse). A whole
    // calldata struct PARAM -> the bound param tuple offset; a struct-array ELEMENT (let d: D = ds[i]) ->
    // the offset-located element base via cdArrayElemBase. Both yield { kind: 'cd', base }.
    let cdBase: string;
    if (init.kind === 'cdStructArrayElem') {
      cdBase = this.cdArrayElemBase(init.arr, init.index, init.type, ctx, out);
    } else if (init.kind === 'cdDynStructValue') {
      // V2 fix: a whole NESTED dynamic-struct FIELD read off a calldata parent (o.inner, `let m: Inner
      // = o.inner`, abi.encode(o.inner)) carries a `place`. Resolve the FIELD's own tuple-start (descend
      // + follow its offset word) - the same base the `return o.inner` echo uses - instead of the PARENT
      // param's tuple start, which decoded the sibling head (splicing the adjacent field into the copy).
      if (init.place) {
        cdBase = this.cdDynStructFieldTupleStart(init.place, struct, ctx, out);
      } else {
        const bound = ctx.cdDynStructs.get(init.param);
        if (!bound) throw new UnsupportedError(`dynamic struct param '${init.param}' is not bound`);
        cdBase = bound.tupleStart;
      }
    } else {
      throw new UnsupportedError(`buildDynStructFromCalldata: unsupported calldata source '${init.kind}'`);
    }
    return this.buildDynStructFromCalldataBase(struct, cdBase, emptyCap, ctx, out);
  }

  /** Decode a DYNAMIC-field struct from a CALLDATA tuple whose tuple-start is `cdBase` into the
   *  POINTER-HEADED image a memDynStruct local consumes. Split out of buildDynStructFromCalldata (the
   *  ctx-aware encodeStaticInline field loop) so a NESTED-DYNAMIC-STRUCT field can recurse on its
   *  resolved sub-tuple base (the calldata twin of buildDynStructFromMemBlob's nested-dyn-struct
   *  branch). Distinct from the ctx-free buildDynStructFromCdBase (the abiDecFromCdToImage twin, which
   *  validates leaves inline): this one preserves buildDynStructFromCalldata's exact well-formed bytes.
   *  `emptyCap` is the context-split cap flavor (BIND -> Panic 0x41, RE-ENCODE -> EMPTY revert); it
   *  propagates unchanged into the recursion. */
  private buildDynStructFromCalldataBase(
    struct: JethType & { kind: 'struct' },
    cdBase: string,
    emptyCap: boolean,
    ctx: LowerCtx,
    out: string[],
  ): string {
    const lenCap = emptyCap ? `revert(0, 0)` : `${this.panic()}(0x41)`;
    const src: TupleSrc = { kind: 'cd', base: cdBase };
    const headWords = tupleHeadWords(struct);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${headWords * 32}))`);
    let hw = 0;
    struct.fields.forEach((f, i) => {
      const at = hw === 0 ? ptr : `add(${ptr}, ${hw * 32})`;
      if (isBytesLike(f.type)) {
        const fref = this.dynFieldRef(f, src, i, hw, ctx, out);
        // a calldata string/bytes field materialized into a fresh image (store/local, NOT the echo
        // path): the echo decoder defers the length-cap + payload-fits checks, so add them here. solc
        // allocs the [len][data] blob via array_allocation_size = add(0x20, round_up(len)) then
        // finalize_allocation, which Panics 0x41 on allocation-SIZE overflow (freePtr + 0x20 +
        // round_up(len) > 0xffffffffffffffff, or the round-up itself wraps). Mirror that SIZE guard here
        // against JETH's ACTUAL free pointer (mload(0x40), == solc's free pointer), with the context-split
        // flavor (lenCap): the BIND context (`let m: R = p`, a calldata->MEMORY deep copy) Panics 0x41 (solc
        // flips at length = 2^64 - 255 for a bytes leaf under this layout, NOT at 2^64); the abi.encode /
        // emit / error RE-ENCODE context -> EMPTY revert (probe-verified vs 0.8.35). The SIZE guard MUST
        // precede the payload-fits check (solc allocs before touching calldata). The 2^64 length cap stays
        // too (subsumed, harmless). The payload-fits check ALWAYS stays an EMPTY revert (a TRUNCATED / OOB
        // source runs past calldatasize; solc empty-reverts there regardless of the alloc-cap flavor).
        if (fref.src === 'calldata') {
          out.push(`if gt(${fref.len}, 0xffffffffffffffff) { ${lenCap} }`);
          const fp = this.fresh();
          out.push(`let ${fp} := mload(0x40)`);
          const blobEnd = this.fresh();
          out.push(`let ${blobEnd} := add(add(${fp}, 0x20), and(add(${fref.len}, 0x1f), not(0x1f)))`);
          out.push(`if or(gt(${blobEnd}, 0xffffffffffffffff), lt(${blobEnd}, ${fp})) { ${lenCap} }`);
          out.push(`if gt(add(${fref.dataPtr}, ${fref.len}), calldatasize()) { revert(0, 0) }`);
        }
        const { mp } = this.toMemory(fref, out);
        out.push(`mstore(${at}, ${mp})`);
        hw += 1;
      } else if (f.type.kind === 'array' && f.type.length === undefined && isStaticValueType(f.type.element)) {
        // a DYNAMIC value-array field: resolve its calldata tail (offset word at base + hw*32;
        // absolute = base + offset, bounded exactly like solc's tuple-member decode), decode +
        // VALIDATE it into a fresh [len][elems] memory image via abiEncFromCd, then store the
        // pointer in the head word (the pointer-headed image writeDynStructFromMem consumes).
        if (src.kind !== 'cd')
          throw new UnsupportedError('calldata dynamic-array struct field decode needs a calldata source');
        const so = this.fresh();
        out.push(`let ${so} := calldataload(${hw === 0 ? src.base : `add(${src.base}, ${hw * 32})`})`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${src.base}, ${so})`);
        out.push(`if gt(add(${se}, ${cdElemHeadBytes(f.type)}), calldatasize()) { revert(0, 0) }`);
        // solc allocates the [len][elems] image via array_allocation_size = add(0x20, mul(len, stride))
        // then finalize_allocation, which Panics 0x41 on allocation-SIZE overflow: when the resulting free
        // pointer add(freePtr, add(0x20, mul(len, stride))) exceeds 0xffffffffffffffff (or the mul itself
        // overflows). Mirror that guard here using JETH's ACTUAL free pointer at the alloc point (mload(0x40),
        // == solc's free pointer for this layout), with the context-split flavor (lenCap): the BIND context
        // (calldata->MEMORY deep copy) hits solc's allocation guard -> Panic 0x41 (probe-verified vs 0.8.35 -
        // solc flips to Panic 0x41 at a length ~2^59 for a u256[] field, NOT at 2^64), the abi.encode / emit /
        // error RE-ENCODE context -> EMPTY revert. The SIZE guard MUST precede the payload-fits check below,
        // exactly like solc allocates before touching calldata (a payload-fits empty-revert must not preempt
        // the alloc Panic). The 2^64 length cap stays too (subsumed by the size cap, but harmless). THEN
        // require the whole [len][elems] payload to lie within calldata (ALWAYS an EMPTY revert for a
        // TRUNCATED / OOB source, like solc). The RE-ENCODE consumer also passes capEmptyRevert into
        // abiEncFromCd below so its own internal caps match.
        const alen = this.fresh();
        out.push(`let ${alen} := calldataload(${se})`);
        out.push(`if gt(${alen}, 0xffffffffffffffff) { ${lenCap} }`);
        const dst = this.fresh();
        out.push(`let ${dst} := mload(0x40)`);
        const encEnd = this.fresh();
        out.push(
          `let ${encEnd} := add(add(${dst}, 0x20), mul(${alen}, ${abiHeadWords(f.type.element) * 32}))`,
        );
        out.push(`if or(gt(${encEnd}, 0xffffffffffffffff), lt(${encEnd}, ${dst})) { ${lenCap} }`);
        out.push(
          `if gt(add(add(${se}, 0x20), mul(${alen}, ${abiHeadWords(f.type.element) * 32})), calldatasize()) { revert(0, 0) }`,
        );
        const size = this.abiEncFromCd(f.type, se, dst, true, out, emptyCap);
        out.push(`mstore(0x40, add(${dst}, ${size}))`);
        out.push(`mstore(${at}, ${dst})`);
        hw += 1;
      } else if (f.type.kind === 'array' && f.type.length === undefined && !isStaticValueType(f.type.element)) {
        // Edge F: a NESTED-DYNAMIC-LEAF array field (bytes[]/string[]/T[][]; the value-array case is
        // caught above). Head word = offset (relative to the tuple start) to the field tail; decode the
        // tail into a fresh B4 pointer-headed image via abiDecFromCdToImage and store ITS absolute pointer
        // (not a relative-offset ABI block) in the head word - the layout the read/encode paths consume.
        // Mirrors buildDynStructFromMemBlob's Cat-C leaf-array branch but from a CALLDATA source. The
        // oversized-LENGTH cap (lenCap) is context-split: the BIND context (calldata->MEMORY deep copy)
        // hits solc's memory allocation guard -> Panic 0x41 (probe-verified vs 0.8.35 - a huge OUTER
        // array count OR a huge inner element length under a bound dyn-struct param Panics 0x41, NOT
        // empty), the abi.encode / emit / error RE-ENCODE context -> EMPTY revert. A TRUNCATED / OOB
        // offset ALWAYS empty-reverts (the payload-fits checks keep revert(0, 0) inside
        // abiDecFromCdToImage regardless of the cap flavor).
        if (src.kind !== 'cd')
          throw new UnsupportedError('calldata leaf-array struct field decode needs a calldata source');
        const so = this.fresh();
        out.push(`let ${so} := calldataload(${hw === 0 ? src.base : `add(${src.base}, ${hw * 32})`})`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${src.base}, ${so})`);
        out.push(`if gt(add(${se}, ${cdElemHeadBytes(f.type)}), calldatasize()) { revert(0, 0) }`);
        const ip = this.fresh();
        out.push(`let ${ip} := ${this.abiDecFromCdToImage(f.type, se, out, lenCap)}`);
        out.push(`mstore(${at}, ${ip})`);
        hw += 1;
      } else if (f.type.kind === 'array' && f.type.length !== undefined && isDynamicType(f.type)) {
        // W5C: a FIXED-outer DYNAMIC-element field (Arr<string,N>): head word = offset (relative to
        // the tuple start) to the field's N-word offset table; decode the tail into a fresh N-pointer
        // fixed image via abiDecFromCdToImage's fixed-of-dynamic branch and store ITS absolute pointer.
        // Mirrors the Edge-F leaf-array branch above (OOB offset / truncated table -> EMPTY revert),
        // with the context-split cap (lenCap) for an oversized inner LENGTH: the BIND context is a
        // calldata->MEMORY deep copy and solc's allocation guard Panics 0x41 there (probe-verified vs
        // 0.8.35 for a huge string length and a huge inner u256[] count under a fixed-outer field); the
        // abi.encode / emit / error RE-ENCODE context reverts EMPTY.
        if (src.kind !== 'cd')
          throw new UnsupportedError('calldata fixed-outer-array struct field decode needs a calldata source');
        const so = this.fresh();
        out.push(`let ${so} := calldataload(${hw === 0 ? src.base : `add(${src.base}, ${hw * 32})`})`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${src.base}, ${so})`);
        out.push(`if gt(add(${se}, ${f.type.length * 32}), calldatasize()) { revert(0, 0) }`);
        const ip = this.fresh();
        out.push(`let ${ip} := ${this.abiDecFromCdToImage(f.type, se, out, lenCap)}`);
        out.push(`mstore(${at}, ${ip})`);
        hw += 1;
      } else if (f.type.kind === 'struct' && isDynamicType(f.type)) {
        // a NESTED DYNAMIC STRUCT field (its own dynamic member makes it pointer-headed): head word =
        // offset (relative to the tuple start) to the field's sub-tuple. Bound it against calldatasize
        // exactly like the sibling dynamic branches (unsigned offset cap + head-fits check), then recurse
        // to build the nested pointer-headed image and store its ABSOLUTE pointer in the head word - the
        // layout memDynField / the encoders consume (the calldata twin of buildDynStructFromMemBlob's
        // nested-dyn-struct branch). Without this branch the static-value else-branch below would feed the
        // offset word to encodeStaticInline, which either miscompiles or throws JETH900. tupleHeadWords
        // counts it as 1. `emptyCap` propagates unchanged (a huge inner length inside the nested struct
        // Panics 0x41 in the BIND context / EMPTY-reverts in the RE-ENCODE context, like a top-level one).
        if (src.kind !== 'cd')
          throw new UnsupportedError('calldata nested-dyn-struct field decode needs a calldata source');
        const so = this.fresh();
        out.push(`let ${so} := calldataload(${hw === 0 ? src.base : `add(${src.base}, ${hw * 32})`})`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${src.base}, ${so})`);
        out.push(`if gt(add(${se}, ${cdElemHeadBytes(f.type)}), calldatasize()) { revert(0, 0) }`);
        const ip = this.buildDynStructFromCalldataBase(f.type, se, emptyCap, ctx, out);
        out.push(`mstore(${at}, ${ip})`);
        hw += 1;
      } else {
        this.encodeStaticInline(f.type, src, i, hw, at, ctx, out);
        hw += abiHeadWords(f.type);
      }
    });
    return ptr;
  }

  /** Decode a DYNAMIC-field struct from an in-MEMORY ABI tuple (the constructor args blob) into the
   *  POINTER-HEADED image a memDynStruct local consumes (value fields inline; a bytes/string or
   *  dynamic-value-array field's head word holds an ABSOLUTE pointer to a fresh [len][data] image).
   *  The memory twin of buildDynStructFromCalldata: reads via mload, bounds every field tail against
   *  `blobEnd` (the absolute end of the args blob), and reuses abiDecFromMem for each tail (so the
   *  short-args / oversized-length revert semantics are byte-identical to solc's memory decode). The
   *  shape is restricted to isSupportedDynStructLocal (value / bytes/string / dynamic value-array
   *  fields), the same set the analyzer admits for a memDynStruct local. `base` is the tuple start. */
  private buildDynStructFromMemBlob(
    struct: JethType & { kind: 'struct' },
    base: string,
    blobEnd: string,
    out: string[],
  ): string {
    const headWords = tupleHeadWords(struct);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${headWords * 32}))`);
    let hw = 0;
    for (const f of struct.fields) {
      const at = hw === 0 ? ptr : `add(${ptr}, ${hw * 32})`;
      const headAt = hw === 0 ? base : `add(${base}, ${hw * 32})`;
      if (
        isBytesLike(f.type) ||
        (f.type.kind === 'array' && f.type.length === undefined && isStaticValueType(f.type.element))
      ) {
        // a dynamic field: head word = offset (relative to the tuple start) to the field tail.
        const so = this.fresh();
        out.push(`let ${so} := mload(${headAt})`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${base}, ${so})`);
        out.push(`if gt(add(${se}, ${cdElemHeadBytes(f.type)}), ${blobEnd}) { revert(0, 0) }`);
        const dst = this.fresh();
        out.push(`let ${dst} := mload(0x40)`);
        const size = this.abiDecFromMem(f.type, se, dst, blobEnd, out);
        out.push(`mstore(0x40, add(${dst}, ${size}))`);
        out.push(`mstore(${at}, ${dst})`);
        hw += 1;
      } else if (f.type.kind === 'array' && f.type.length === undefined) {
        // Cat C: a NESTED-DYNAMIC-LEAF array field (bytes[]/string[]/T[][]). Head word = offset (relative
        // to the tuple start) to the field tail; decode the tail into a fresh B4 pointer-headed image via
        // abiDecFromMemToImage and store ITS absolute pointer (not a relative-offset ABI block) in the
        // head word - the layout the read/encode paths consume. Same OOB/cap revert semantics as solc.
        const so = this.fresh();
        out.push(`let ${so} := mload(${headAt})`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${base}, ${so})`);
        out.push(`if gt(add(${se}, ${cdElemHeadBytes(f.type)}), ${blobEnd}) { revert(0, 0) }`);
        const ip = this.fresh();
        out.push(`let ${ip} := ${this.abiDecFromMemToImage(f.type, se, blobEnd, out)}`);
        out.push(`mstore(${at}, ${ip})`);
        hw += 1;
      } else if (f.type.kind === 'array' && f.type.length !== undefined && isDynamicType(f.type)) {
        // W5C: a FIXED-outer DYNAMIC-element field (Arr<string,N>): head word = offset (relative to the
        // tuple start) to the field's N-word offset table; decode it into a fresh N-pointer fixed image
        // via abiDecFromMemToImage's fixed-of-dynamic branch, store ITS absolute pointer. Mirrors the
        // Cat-C branch above (the N-word table is bounded against the blob end, like solc).
        const so = this.fresh();
        out.push(`let ${so} := mload(${headAt})`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${base}, ${so})`);
        out.push(`if gt(add(${se}, ${f.type.length * 32}), ${blobEnd}) { revert(0, 0) }`);
        const ip = this.fresh();
        out.push(`let ${ip} := ${this.abiDecFromMemToImage(f.type, se, blobEnd, out)}`);
        out.push(`mstore(${at}, ${ip})`);
        hw += 1;
      } else if (f.type.kind === 'struct' && isDynamicType(f.type)) {
        // a NESTED DYNAMIC STRUCT field (its own dynamic member makes it pointer-headed): head word =
        // offset (relative to the tuple start) to the field's sub-tuple. Bound it against blobEnd exactly
        // like the sibling dynamic branches, then recurse to build the nested pointer-headed image (value
        // fields inline + validated, its own dynamic fields head pointers) and store the sub-image's
        // ABSOLUTE pointer in the head word - the layout memDynField / the encoders consume (the same shape
        // buildDynStructFromStorage's nested-dyn-struct branch stores). tupleHeadWords counts it as 1.
        // (The static-value else-branch below would feed the offset word to abiDecFromMem as inline data,
        // which reverts - the P0-10 miscompile: JETH empty-reverts where solc returns the value.)
        const so = this.fresh();
        out.push(`let ${so} := mload(${headAt})`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${base}, ${so})`);
        out.push(`if gt(add(${se}, ${cdElemHeadBytes(f.type)}), ${blobEnd}) { revert(0, 0) }`);
        const ip = this.buildDynStructFromMemBlob(f.type, se, blobEnd, out);
        out.push(`mstore(${at}, ${ip})`);
        hw += 1;
      } else {
        // a static value field: one validated word, inline (abiDecFromMem validates dirty bits).
        this.abiDecFromMem(f.type, headAt, at, blobEnd, out);
        hw += abiHeadWords(f.type);
      }
    }
    return ptr;
  }

  /** Write a constructed static aggregate (structNew / arrayLit, possibly nested) into the
   *  memory image at `ptr`, starting at word `wordBase`. Value leaves are one word each. */
  // ---- W6A: inline-aggregate capture soundness ------------------------------------------------
  // JETH's STATIC struct / fixed-array memory image is FLAT (one word per ABI leaf), so a
  // struct/fixed-array FIELD of a constructed aggregate is stored INLINE by copying the source's
  // words. Solidity memory-to-memory assignment is BY REFERENCE: solc stores the source's POINTER,
  // so later mutations of the source (or of the field) are visible through BOTH names. Copying an
  // ALIASABLE memory source into an inline field therefore MISCOMPILES whenever the constructed
  // value outlives the expression (a local binding, an internal-call argument, a memory element
  // store, an internal return). When the image is provably TRANSIENT - consumed immediately and
  // atomically by an ABI encoder (external return / abi.encode / event / error) or a storage deep
  // copy, with no user code between materialization and consumption - the copy is unobservable and
  // stays accepted. `inlineCaptureTransient` marks those lowering regions; internal-call argument
  // materialization RESETS it (a callee can mutate an argument image even inside an encode).
  private inlineCaptureTransient = false;

  /** Run `fn` with the inline-capture context marked TRANSIENT (the materialized image is consumed
   *  immediately and atomically; an aliasing copy is unobservable). Restores the previous mark. */
  private inTransientCapture<T>(fn: () => T): T {
    const prev = this.inlineCaptureTransient;
    this.inlineCaptureTransient = true;
    try {
      return fn();
    } finally {
      this.inlineCaptureTransient = prev;
    }
  }

  /** Run `fn` with the inline-capture context FORCED back to PERSISTENT (used by internal-call
   *  argument materialization inside an otherwise-transient encode region: the callee receives the
   *  image and can mutate it / expect writes through the captured source). W7A: capture-patch
   *  recording is also suspended - a callee-arg image is the callee's own value, not a component
   *  of the enclosing two-phase encode. */
  private inPersistentCapture<T>(fn: () => T): T {
    const prev = this.inlineCaptureTransient;
    const prevPatches = this.twoPhasePatches;
    this.inlineCaptureTransient = false;
    this.twoPhasePatches = null;
    try {
      return fn();
    } finally {
      this.inlineCaptureTransient = prev;
      this.twoPhasePatches = prevPatches;
    }
  }

  // ---- W7A two-phase encode: capture patches --------------------------------
  // solc's ABI-encoding consumers (abi.encode*/emit/revert/external tuple returns) evaluate every
  // component LEFT-TO-RIGHT to a value or a REFERENCE handle first, and only then SERIALIZE,
  // reading through the handles LATE (after every sibling's side effects). JETH's flat static
  // images and pointer-headed dyn-struct images freeze a ref-captured memory aggregate at the
  // argument's own position instead. While a two-phase consumer runs its phase 1, the inline-copy
  // sites (writeAggToMem / allocDynStructToMem) record a PATCH for each such freeze; the consumer
  // flushes them (one late re-copy per capture, reading through the captured live pointer) after
  // phase 1 and before serialization, making the frozen image byte-identical to solc's late read.
  private twoPhasePatches: { dst: string; src: string; bytes: number }[] | null = null;

  /** Begin a two-phase consumer's phase 1 (start collecting capture patches). Returns the
   *  enclosing consumer's list so nested consumers stay self-contained. */
  private beginTwoPhase(): { dst: string; src: string; bytes: number }[] | null {
    const prev = this.twoPhasePatches;
    this.twoPhasePatches = [];
    return prev;
  }

  /** End phase 1: emit the recorded late re-copies and restore the enclosing list. */
  private flushTwoPhase(prev: { dst: string; src: string; bytes: number }[] | null, out: string[]): void {
    for (const p of this.twoPhasePatches ?? []) out.push(`mcopy(${p.dst}, ${p.src}, ${p.bytes})`);
    this.twoPhasePatches = prev;
  }

  /** Run `fn` with capture-patch recording suspended. Used around SWITCH-BRANCH materializations
   *  (aggregate ternaries): a patch recorded inside a case block would reference block-scoped Yul
   *  locals from the top-level flush site (out-of-scope). Those rare arms keep the frozen-copy
   *  behavior. */
  private withoutCapturePatches<T>(fn: () => T): T {
    const prev = this.twoPhasePatches;
    this.twoPhasePatches = null;
    try {
      return fn();
    } finally {
      this.twoPhasePatches = prev;
    }
  }

  /** Record a late re-copy for a live memory aggregate `arg` frozen into `dst` from pointer `src`
   *  (both Yul expressions over TOP-LEVEL locals). No-op outside a two-phase phase 1 or for
   *  alias-safe (copy-by-value) sources - those are copies in solc too. */
  private recordCapturePatch(arg: Expr, dst: string, src: string, bytes: number): void {
    if (this.twoPhasePatches === null) return;
    if (this.isAliasSafeAggCaptureSource(arg)) return;
    this.twoPhasePatches.push({ dst, src, bytes });
  }

  /** True when copying `e` into an inline aggregate field/element position matches solc's OWN
   *  semantics (solc also deep-copies these sources into memory): a STORAGE struct/array value, a
   *  CALLDATA aggregate, or a freshly-decoded blob. Everything else (a memory local / param /
   *  element / field, an internal-call result, a mixed ternary, or an unknown kind) is - or may
   *  be - a live memory REFERENCE that solc would alias, so a flat copy is unsound. */
  private isAliasSafeAggCaptureSource(e: Expr): boolean {
    switch (e.kind) {
      case 'structNew':
      case 'arrayLit':
        // inline constructions are fresh by definition; their OWN args are checked recursively
        // where they are written.
        return true;
      case 'structValue':
      case 'mapStorageValue':
      case 'structArrayElem':
      case 'placeRead':
      case 'cdAggregateValue':
      case 'cdStructArrayElem':
      case 'cdAggArrayElem':
      case 'cdFieldAggValue':
      case 'cdNestedFieldAggValue':
      case 'abiDecode':
        return true;
      case 'arrayValue': {
        const b = e.arr.base.kind;
        return (
          b === 'fixedArray' ||
          b === 'stateArray' ||
          b === 'mapArray' ||
          b === 'placeArray' ||
          b === 'calldataArray' ||
          b === 'cdDynFixedDynField'
        );
      }
      case 'ternary':
        return this.isAliasSafeAggCaptureSource(e.then) && this.isAliasSafeAggCaptureSource(e.else);
      default:
        return false;
    }
  }

  /** W6A soundness gate at the inline-copy sites: reject (JETH465) capturing an aliasable memory
   *  aggregate into an inline field/element of a constructed aggregate in a PERSISTENT context.
   *  solc stores a reference there; JETH's flat static image cannot, so a clean reject beats the
   *  silent copy the old code emitted (a confirmed miscompile family: mutations through either
   *  name diverged). Transient (immediate-encode / storage-store) contexts keep the copy. */
  private assertInlineAggCaptureSound(arg: Expr, what: string, fieldType?: JethType): void {
    // A POINTER-HEADED static-struct fixed array field/element (Arr<In,N>, In a static struct, and
    // nested Arr<Arr<In,N>,M>) is laid out in memory as N absolute-pointer words (one per element,
    // NO inline length header), but its tuple-head/return image is the elements INLINE. The flat
    // mcopy at the caller copies abiHeadWords(fieldType)*32 bytes STRAIGHT from the memory image, so
    // it would emit the element POINTERS (plus trailing garbage) instead of the inline element words
    // - a payload-dropping MISCOMPILE. An INLINE arrayLit source never reaches here (it recurses
    // element-by-element); only a NON-INLINE source (a memory local/field/element, a call, ...) does,
    // and no flat copy reproduces solc's inline layout. Reject with JETH465, the SAME code the
    // var-bound form (`let s: S = S(9n, a); return s`) already emits, so the inline-constructor form
    // is consistent. This fires even in a TRANSIENT (immediate-encode / return) context: unlike the
    // aliasing hazard below, the layout mismatch corrupts regardless of transience.
    if (fieldType !== undefined && fieldType.kind === 'array' && isStaticStructFixedLeafArray(fieldType)) {
      throw new UnsupportedError(
        `cannot inline a pointer-headed static-struct fixed-array value ('${arg.kind}') into ${what}: ` +
          `Solidity lays the elements out inline in the aggregate's tuple head while JETH's memory image ` +
          `is one absolute-pointer word per element, so a flat copy would emit the element pointers ` +
          `instead of the element data (dropping the payload). Construct the field inline, or return / ` +
          `abi.encode the array on its own`,
        'JETH465',
      );
    }
    if (this.inlineCaptureTransient) return;
    if (this.isAliasSafeAggCaptureSource(arg)) return;
    throw new UnsupportedError(
      `cannot capture a memory aggregate value ('${arg.kind}') into ${what}: Solidity stores a live ` +
        `reference here while JETH's inline (flat) image would freeze a copy, so aliasing mutations ` +
        `would diverge from solc. Construct the field/element inline, copy the data into a fresh ` +
        `constructor argument, or use a dynamic (pointer-headed) struct field instead`,
      'JETH465',
    );
  }

  /** True if a constructed aggregate (structNew / arrayLit) has, at any depth, an aggregate field /
   *  element supplied from a NON-INLINE source (not an inline structNew / arrayLit). Such a value must
   *  be built in FRESH memory (allocAggToMem) rather than the memory-0 return scratch, since
   *  materializing the source would otherwise clobber the in-progress blob. */
  private aggHasNonInlineField(v: Expr): boolean {
    if (v.kind === 'structNew') {
      return (v.type as JethType & { kind: 'struct' }).fields.some((f, i) => {
        const a = v.args[i]!;
        if (!(f.type.kind === 'struct' || (f.type.kind === 'array' && f.type.length !== undefined))) return false;
        if (a.kind !== 'structNew' && a.kind !== 'arrayLit') return true;
        return this.aggHasNonInlineField(a);
      });
    }
    if (v.kind === 'arrayLit') {
      const aggElem = v.elem.kind === 'struct' || (v.elem.kind === 'array' && v.elem.length !== undefined);
      if (!aggElem) return false;
      return v.elements.some(
        (el) => (el.kind !== 'structNew' && el.kind !== 'arrayLit') || this.aggHasNonInlineField(el),
      );
    }
    return false;
  }

  private writeAggToMem(value: Expr, ptr: string, wordBase: number, ctx: LowerCtx, out: string[]): void {
    const at = (w: number): string => (w === 0 ? ptr : `add(${ptr}, ${w * 32})`);
    if (value.kind === 'structNew') {
      let w = wordBase;
      value.fields.forEach((f, j) => {
        const arg = value.args[j]!;
        if (arg.kind === 'arrayLit' || arg.kind === 'structNew') this.writeAggToMem(arg, ptr, w, ctx, out);
        else if (f.type.kind === 'struct' || (f.type.kind === 'array' && f.type.length !== undefined)) {
          // a non-inline aggregate field source: materialize its ABI-unpacked image (fresh memory,
          // past this parent), then mcopy it into the field's words. W6A: this flat copy is only
          // sound for a copy-by-value source (storage/calldata/decode) or a transient consumer;
          // an aliasable memory source in a persistent context REJECTS (solc stores a reference).
          // W7A: inside a two-phase encode's phase 1 a live-memory source additionally records a
          // capture patch (a late re-copy through the same pointer, after all sibling effects).
          this.assertInlineAggCaptureSound(arg, `constructed struct field '${f.name}'`, f.type);
          const fldSrc = this.aggToMemPtr(arg, ctx, out);
          out.push(`mcopy(${at(w)}, ${fldSrc}, ${abiHeadWords(f.type) * 32})`);
          this.recordCapturePatch(arg, at(w), fldSrc, abiHeadWords(f.type) * 32);
        } else out.push(`mstore(${at(w)}, ${this.lowerExpr(arg, ctx, out)})`);
        w += abiHeadWords(f.type);
      });
      return;
    }
    if (value.kind === 'arrayLit') {
      const ew = abiHeadWords(value.elem);
      const aggElem = value.elem.kind === 'struct' || (value.elem.kind === 'array' && value.elem.length !== undefined);
      value.elements.forEach((el, k) => {
        const w = wordBase + k * ew;
        if (el.kind === 'arrayLit' || el.kind === 'structNew') this.writeAggToMem(el, ptr, w, ctx, out);
        else if (aggElem) {
          // W6A: an aggregate ELEMENT of an inline fixed-array literal ([p, q] as a constructed
          // field / a nested literal) has the same flat-copy-vs-reference hazard as a field.
          // W7A: record a capture patch inside a two-phase encode's phase 1 (late re-copy).
          this.assertInlineAggCaptureSound(el, 'a constructed fixed-array element', value.elem);
          const elSrc = this.aggToMemPtr(el, ctx, out);
          out.push(`mcopy(${at(w)}, ${elSrc}, ${ew * 32})`);
          this.recordCapturePatch(el, at(w), elSrc, ew * 32);
        } else out.push(`mstore(${at(w)}, ${this.lowerExpr(el, ctx, out)})`);
      });
      return;
    }
    throw new UnsupportedError(`cannot write '${value.kind}' into a memory aggregate`);
  }

  /** Write a (possibly NESTED) static fixed-array literal into storage at `baseSlot`.
   *  Value elements use arrayElemStore (handles packing); nested array / struct elements
   *  recurse at baseSlot + k*slotCount(element). W7B: two-phase - every element expression
   *  (including each struct element's ctor args) is evaluated FIRST in source order, then all
   *  the storage writes run (solc builds the literal in memory before the storage copy). */
  private writeArrayLit(lit: Expr & { kind: 'arrayLit' }, baseSlot: string, ctx: LowerCtx, out: string[]): void {
    const items = this.prepareLitElems(lit, ctx, out);
    this.emitPreparedLitStore(lit, items, baseSlot, out);
  }

  /** Bounds-checked storage slot of a whole STRUCT array element this.recs[i] (a
   *  storage/fixed/mapping-valued struct array). Struct elements are never packed: the
   *  element occupies storageSlotCount(elem) contiguous slots at data + i*slotCount
   *  (dynamic/mapping array) or baseSlot + i*slotCount (fixed array). Panic(0x32) on OOB. */
  private structArrayElemSlot(arr: ArrayExpr, index: Expr, ctx: LowerCtx, out: string[]): string {
    const ref = this.lowerArrayRef(arr, ctx, out);
    const sc = storageSlotCount(arr.elem);
    const i = this.fresh();
    out.push(`let ${i} := ${this.lowerExpr(index, ctx, out)}`);
    const slot = this.fresh();
    if (ref.src === 'fixed') {
      out.push(`if iszero(lt(${i}, ${ref.length})) { ${this.panic()}(0x32) }`);
      out.push(`let ${slot} := add(${ref.baseSlot}, mul(${i}, ${sc}))`);
      return slot;
    }
    if (ref.src === 'storage') {
      out.push(`if iszero(lt(${i}, sload(${ref.lenSlot}))) { ${this.panic()}(0x32) }`);
      const data = this.arrayDataSlot(ref.lenSlot, out);
      out.push(`let ${slot} := add(${data}, mul(${i}, ${sc}))`);
      return slot;
    }
    throw new UnsupportedError('a struct element of a calldata array is not a storage place');
  }

  /** Resolve the length slot of a dynamic-array VALUE source (for a storage-to-storage
   *  array copy): a state array (arrayValue/stateArray), a mapping-valued array
   *  (arrayValue/mapArray or mapStorageValue at the runtime keccak(key.base) slot). */
  private arraySrcLenSlot(value: Expr, ctx: LowerCtx, out: string[]): string {
    if (value.kind === 'arrayValue') {
      if (value.arr.base.kind === 'stateArray') return String(value.arr.base.slot);
      if (value.arr.base.kind === 'mapArray')
        return this.mappingSlot(value.arr.base.baseSlot, value.arr.base.keys, ctx, out);
      if (value.arr.base.kind === 'placeArray') return this.lowerPlace(value.arr.base.path, ctx, out).slot;
    }
    if (value.kind === 'mapStorageValue') return this.mappingSlot(value.baseSlot, value.keys, ctx, out);
    throw new UnsupportedError(`cannot copy an array from '${value.kind}'`);
  }

  /** Storage-to-storage DEEP copy of a dynamic array from `srcLenSlot` to `dstLenSlot`
   *  (length-slot exprs). Resizes the dest to the source length, copies every element,
   *  and clears the dest's freed tail - byte-identical to solc's array assignment.
   *  - static elements (value packed/unpacked, static struct): copy the contiguous data
   *    slots verbatim (the source's zero-padded last packed slot clears any dest element
   *    that fell beyond the new length), then zero the dest's excess data slots.
   *  - dynamic elements (bytes/string, dynamic struct, nested dynamic array): per element,
   *    storeDynamic / copyStruct / recursive copyArray-copyFixedArray (overwrite-clearing each
   *    element's old tail); the freed tail elements are deep-cleared first (clearStr for bytes/string,
   *    deleteStruct for a struct element, deleteAgg for a nested-array element). */
  private copyArray(elem: JethType, srcLenSlot: string, dstLenSlot: string, out: string[]): void {
    const srcLen = this.fresh();
    const dstLen = this.fresh();
    out.push(`let ${srcLen} := sload(${srcLenSlot})`);
    out.push(`let ${dstLen} := sload(${dstLenSlot})`);
    const srcData = this.fresh();
    const dstData = this.fresh();
    out.push(`let ${srcData} := ${this.arrayDataSlotHelper()}(${srcLenSlot})`);
    out.push(`let ${dstData} := ${this.arrayDataSlotHelper()}(${dstLenSlot})`);

    if (isStaticType(elem)) {
      const packs = arrayElemPacks(elem);
      const slotsFor = (L: string): string =>
        packs.packed
          ? `div(add(${L}, ${packs.perSlot - 1}), ${packs.perSlot})`
          : `mul(${L}, ${storageSlotCount(elem)})`;
      const srcSlots = this.fresh();
      const dstSlots = this.fresh();
      out.push(`let ${srcSlots} := ${slotsFor(srcLen)}`);
      out.push(`let ${dstSlots} := ${slotsFor(dstLen)}`);
      const i = this.fresh();
      out.push(
        `for { let ${i} := 0 } lt(${i}, ${srcSlots}) { ${i} := add(${i}, 1) } { sstore(add(${dstData}, ${i}), sload(add(${srcData}, ${i}))) }`,
      );
      const j = this.fresh();
      out.push(
        `for { let ${j} := ${srcSlots} } lt(${j}, ${dstSlots}) { ${j} := add(${j}, 1) } { sstore(add(${dstData}, ${j}), 0) }`,
      );
      out.push(`sstore(${dstLenSlot}, ${srcLen})`);
      return;
    }

    // dynamic elements: per-element (sc slots each).
    const sc = storageSlotCount(elem);
    const k = this.fresh();
    out.push(`for { let ${k} := ${srcLen} } lt(${k}, ${dstLen}) { ${k} := add(${k}, 1) } {`);
    const clearInner: string[] = [];
    const ceb = this.fresh();
    clearInner.push(`let ${ceb} := add(${dstData}, mul(${k}, ${sc}))`);
    if (isBytesLike(elem)) {
      clearInner.push(`${this.clearStr()}(${ceb})`);
    } else if (elem.kind === 'array') {
      // a dynamic-array / dynamic-leaf-fixed-array element (T[][], Arr<string,N>[]): recurse into the
      // full delete machinery (frees each element's keccak data + zeroes its header footprint).
      this.deleteAgg(elem, ceb, clearInner);
    } else {
      // a dynamic struct element: full recursive delete (frees bytes/string keccak long-data AND each
      // dynamic-array field's keccak data region, then zeroes value fields) - matches solc's element
      // delete and prevents stale-tail data on shrink. deleteStruct clears the whole element footprint,
      // so no separate inline-slot zero loop is needed.
      this.deleteStruct(elem as JethType & { kind: 'struct' }, ceb, clearInner);
    }
    for (const l of clearInner) out.push('  ' + l);
    out.push('}');
    out.push(`sstore(${dstLenSlot}, ${srcLen})`);
    const m = this.fresh();
    out.push(`for { let ${m} := 0 } lt(${m}, ${srcLen}) { ${m} := add(${m}, 1) } {`);
    const copyInner: string[] = [];
    const seb = this.fresh();
    const deb = this.fresh();
    copyInner.push(`let ${seb} := add(${srcData}, mul(${m}, ${sc}))`);
    copyInner.push(`let ${deb} := add(${dstData}, mul(${m}, ${sc}))`);
    if (isBytesLike(elem)) {
      this.storeDynamic(deb, { src: 'storage', slot: seb }, copyInner);
    } else if (elem.kind === 'array' && elem.length === undefined) {
      // a dynamic-array element (T[][]): the element IS a length-headed dynamic array -> recurse.
      this.copyArray(elem.element, seb, deb, copyInner);
    } else if (elem.kind === 'array') {
      // a dynamic-leaf fixed-array element (Arr<string,N>[]): per-element deep copy.
      this.copyFixedArray(elem, seb, deb, copyInner);
    } else {
      this.copyStruct(elem as JethType & { kind: 'struct' }, seb, deb, copyInner);
    }
    for (const l of copyInner) out.push('  ' + l);
    out.push('}');
  }

  /** Resolve the storage base slot of a whole FIXED-array source value (state-var fixed array,
   *  or a nested fixed-array field via placeArray). */
  private fixedArraySrcBase(value: Expr, ctx: LowerCtx, out: string[]): string {
    if (value.kind === 'arrayValue') {
      const base = value.arr.base;
      if (base.kind === 'fixedArray') return String(base.baseSlot);
      if (base.kind === 'stateArray') return String(base.slot);
      if (base.kind === 'placeArray') return this.lowerPlace(base.path, ctx, out).slot;
      if (base.kind === 'mapArray') return this.mappingSlot(base.baseSlot, base.keys, ctx, out);
    }
    // a whole fixed-array reached as an element of a dynamic/fixed array (this.a[i], Arr<T,N>[]) or as a
    // mapping value (this.m[k], mapping(K=>Arr<T,N>)): resolve its (runtime) base slot.
    if (value.kind === 'structArrayElem') return this.structArrayElemSlot(value.arr, value.index, ctx, out);
    if (value.kind === 'mapStorageValue') return this.mappingSlot(value.baseSlot, value.keys, ctx, out);
    throw new UnsupportedError(`cannot copy a fixed array from '${value.kind}'`);
  }

  /** Storage-to-storage copy of a fixed array Arr<T,N> from `srcBase` to `dstBase`. Static
   *  elements (value/packed/static struct/static nested array) copy the array's slot footprint
   *  verbatim; dynamic elements (bytes/string, dynamic struct) deep-copy per element (storeDynamic
   *  / copyStruct overwrite-clear the dst element's old tail). Byte-identical to solc. */
  private copyFixedArray(arrType: JethType & { kind: 'array' }, srcBase: string, dstBase: string, out: string[]): void {
    const elem = arrType.element;
    const N = arrType.length!;
    const sConst = /^\d+$/.test(srcBase);
    const dConst = /^\d+$/.test(dstBase);
    const sAt = (n: number): string =>
      sConst ? String(BigInt(srcBase) + BigInt(n)) : n === 0 ? srcBase : `add(${srcBase}, ${n})`;
    const dAt = (n: number): string =>
      dConst ? String(BigInt(dstBase) + BigInt(n)) : n === 0 ? dstBase : `add(${dstBase}, ${n})`;
    if (isStaticType(elem)) {
      const slots = storageSlotCount(arrType);
      for (let i = 0; i < slots; i++) out.push(`sstore(${dAt(i)}, sload(${sAt(i)}))`);
      return;
    }
    const sc = storageSlotCount(elem);
    for (let i = 0; i < N; i++) {
      if (isBytesLike(elem)) this.storeDynamic(dAt(i * sc), { src: 'storage', slot: sAt(i * sc) }, out);
      else if (elem.kind === 'array' && elem.length === undefined) this.copyArray(elem.element, sAt(i * sc), dAt(i * sc), out);
      else if (elem.kind === 'array') this.copyFixedArray(elem, sAt(i * sc), dAt(i * sc), out);
      else this.copyStruct(elem as JethType & { kind: 'struct' }, sAt(i * sc), dAt(i * sc), out);
    }
  }

  /** NF-1: write a whole @state Arr<string,N> / Arr<bytes,N> (and nested Arr<Arr<string,N>,M>,
   *  Arr<string[],N>) from a MEMORY pointer-headed image into its N CONSECUTIVE base slots. The image
   *  is N absolute-pointer words (NO [len] header, isDynBytesFixedLeafArray's layout), each word at
   *  `memPtr + i*32` pointing to the i-th element's own image: a [len][data] blob for a bytes/string
   *  leaf, or a sub-image for a nested array element. Each element storage-writes through the SAME
   *  codec the corresponding single-element store uses, so each element OVERWRITE-CLEARS its old tail
   *  (long->short frees the freed keccak data slots) - byte-identical to solc's `stringArr = memArr`. */
  private storeDynLeafFixedArrayFromMem(
    arrType: JethType & { kind: 'array' },
    memPtr: string,
    dstBase: string,
    out: string[],
  ): void {
    const elem = arrType.element;
    const N = arrType.length!;
    const sc = storageSlotCount(elem); // slots per element: 1 for string/bytes/string[]; M for Arr<string,M>
    const dConst = /^\d+$/.test(dstBase);
    const dAt = (n: number): string =>
      dConst ? String(BigInt(dstBase) + BigInt(n)) : n === 0 ? dstBase : `add(${dstBase}, ${n})`;
    for (let i = 0; i < N; i++) {
      const ep = this.fresh();
      out.push(`let ${ep} := mload(add(${memPtr}, ${i * 32}))`); // the i-th element's image pointer
      const deb = dAt(i * sc);
      if (isBytesLike(elem)) {
        // a bytes/string element: ep -> a [len][data] blob. storeDynamic overwrite-clears the dst
        // element's old tail (the single-string storage-write codec, byte-identical to solc).
        this.storeDynamic(deb, { src: 'memory', ptr: ep }, out);
      } else if (elem.kind === 'array' && elem.length !== undefined) {
        // a nested FIXED dyn-leaf array element (Arr<string,M>): recurse (ep is that sub-image's base).
        this.storeDynLeafFixedArrayFromMem(elem, ep, deb, out);
      } else if (elem.kind === 'array' && elem.length === undefined) {
        // a nested DYNAMIC array element (string[]/bytes[]/T[][]): ep -> a [len][...] image; deep-copy
        // into the dst dynamic array (length at deb, data at keccak(deb)) via the existing mem->storage
        // array codecs (resize + per-element deep-write + tail clear), byte-identical to solc.
        if (isStaticValueType(elem.element)) this.copyMemArrayIntoStorage(elem.element, ep, deb, out);
        else this.copyMemAggArrayIntoStorage(elem.element, ep, deb, out);
      } else {
        throw new UnsupportedError(
          `storing a fixed dynamic-leaf array element '${elem.kind}' from a memory source is not supported yet`,
        );
      }
    }
  }

  /** Resolve the storage base slot of a struct VALUE source (for a storage-to-storage
   *  copy): a state-var struct (structValue), a whole mapping-value struct
   *  (mapStorageValue at the runtime keccak(key.base) slot), or a whole struct array
   *  element (structArrayElem at data + i*slotCount). */
  /** Write a whole struct VALUE into a storage slot. Dispatches by source: a constructor
   *  (structNew) is written field-by-field; a MEMORY / CALLDATA struct (memAggregate from a
   *  `let m: S = ...` local, or a calldata struct param) is transcoded from its ABI-unpacked image
   *  into packed storage; a STORAGE struct lvalue is a storage-to-storage deep copy. */
  private storeStructTo(
    type: JethType & { kind: 'struct' },
    value: Expr,
    dst: string,
    ctx: LowerCtx,
    out: string[],
  ): void {
    // W7B: two-phase (evaluate the RHS completely, then store) so a self-reading ctor arg sees
    // the destination's OLD data. `dst` must already be resolved side-effect-free here; callers
    // whose destination resolution can read/mutate state (mapping key, array index, place path)
    // call prepareStructStore FIRST, then resolve dst, then emitPreparedStructStore (RHS-first,
    // the pinned solc order - P4/P29/P30).
    const prep = this.prepareStructStore(type, value, ctx, out);
    this.emitPreparedStructStore(type, prep, dst, out);
  }

  /** W7B phase 1 for a whole-struct RHS: evaluate the value completely per solc's semantics -
   *  a constructor evaluates its args in source order (prepareCtorArgs); a memory/calldata
   *  source materializes/aliases its image; a storage source resolves its base slot (including
   *  any element bounds check, at the ARG position - ps.push(ps[0]) on empty panics like solc). */
  private prepareStructStore(
    type: JethType & { kind: 'struct' },
    value: Expr,
    ctx: LowerCtx,
    out: string[],
  ): PreparedStructStore {
    if (value.kind === 'structNew') {
      // W6A: the constructed value goes straight into storage (a deep copy in solc too) - a
      // TRANSIENT capture context, so an aliasable memory field source stays accepted.
      return {
        k: 'ctor',
        fields: value.fields,
        items: this.inTransientCapture(() => this.prepareCtorArgs(value.fields, value.args, ctx, out)),
      };
    }
    if (value.kind === 'memAggregate' || value.kind === 'cdAggregateValue') {
      // a STATIC struct from a memory/calldata source: its ABI-unpacked image (memory aliases).
      return { k: 'memStatic', ptr: this.aggToMemPtr(value, ctx, out) };
    }
    if (value.kind === 'arrayGet') {
      // W3-Y2c: a MEMORY struct-ARRAY ELEMENT source (this.p0 = ps[i], ps: Arr<P,N> / P[]).
      // ps[i] (arrayGet) lowers to the element's pointer-headed image; aggToMemPtr freezes that
      // pointer. A STATIC struct element transcodes its ABI-unpacked image to packed storage; a
      // DYNAMIC-field element writes value fields packed + dynamic fields with overwrite-clear.
      const mp = this.aggToMemPtr(value, ctx, out);
      return isDynamicType(type) ? { k: 'memDyn', ptr: mp } : { k: 'memStatic', ptr: mp };
    }
    if (
      value.kind === 'memDynStructValue' ||
      value.kind === 'cdDynStructValue' ||
      value.kind === 'memDynField' ||
      value.kind === 'memDynNestedField'
    ) {
      // a DYNAMIC-field struct from a memory local, calldata param, or a whole nested-dyn-struct
      // field of a dyn-struct local (this.d = v.t / this.m[k] = v.t): materialize the
      // pointer-headed image (buildDynStructLocal aliases a memory source's image pointer).
      return { k: 'memDyn', ptr: this.buildDynStructLocal(type, value, ctx, out) };
    }
    return { k: 'storageCopy', srcSlot: this.structSrcSlot(value, ctx, out) };
  }

  /** W7B phase 2 for a whole-struct RHS: the pure store at `dst` (no argument evaluation left). */
  private emitPreparedStructStore(
    type: JethType & { kind: 'struct' },
    prep: PreparedStructStore,
    dst: string,
    out: string[],
  ): void {
    if (prep.k === 'ctor') this.emitPreparedCtorStore(prep.fields, prep.items, dst, out);
    else if (prep.k === 'memStatic') this.storeStaticAggFromMem(type, prep.ptr, dst, out);
    else if (prep.k === 'memDyn') this.writeDynStructFromMem(type, prep.ptr, dst, out);
    else this.copyStruct(type, prep.srcSlot, dst, out);
  }

  /** Write a DYNAMIC-field struct's pointer-headed memory image (from buildDynStructLocal) into
   *  storage: each value field via storeState (packed), each bytes/string field via storeDynamic from
   *  the head-word pointer (overwrite-clearing the old tail). Scoped to value + bytes/string fields;
   *  a dynamic-array field from a memory/calldata source is a later step (clean rejection). */
  private writeDynStructFromMem(
    struct: JethType & { kind: 'struct' },
    memPtr: string,
    slot: string,
    out: string[],
  ): void {
    const sConst = /^\d+$/.test(slot);
    const fslotAt = (n: number): string =>
      n === 0 ? slot : sConst ? String(BigInt(slot) + BigInt(n)) : `add(${slot}, ${n})`;
    let hw = 0;
    for (const f of struct.fields) {
      const at = hw === 0 ? memPtr : `add(${memPtr}, ${hw * 32})`;
      if (isBytesLike(f.type)) {
        const p = this.fresh();
        out.push(`let ${p} := mload(${at})`);
        this.storeDynamic(fslotAt(f.slot), { src: 'memory', ptr: p }, out);
      } else if (!isDynamicType(f.type) && isStaticValueType(f.type)) {
        const w = this.fresh();
        out.push(`let ${w} := mload(${at})`);
        for (const l of this.storeState(f.type, fslotAt(f.slot), f.offset, w)) out.push(l);
      } else if (f.type.kind === 'array' && f.type.length === undefined) {
        // a dynamic-array field: the head word is the memory image pointer. A value-element array
        // ([len][elems]) deep-copies via copyMemArrayIntoStorage; a nested-dynamic-leaf array
        // (bytes[]/string[]/T[][], a pointer-headed B4 image) deep-copies via copyMemAggArrayIntoStorage.
        // Both target the field's storage dynamic array (length at fslot, data at keccak(fslot)),
        // byte-identical to solc (the same helpers `this.field = arr` uses).
        const p = this.fresh();
        out.push(`let ${p} := mload(${at})`);
        if (isStaticValueType(f.type.element)) this.copyMemArrayIntoStorage(f.type.element, p, fslotAt(f.slot), out);
        else this.copyMemAggArrayIntoStorage(f.type.element, p, fslotAt(f.slot), out);
      } else if (f.type.kind === 'array' && f.type.length !== undefined && isDynLeafFixedArray(f.type)) {
        // W5C: a FIXED-outer DYNAMIC-element field (Arr<string,N>): the head word holds the N-pointer
        // fixed-image pointer; write it into the field's N consecutive storage slots via the NF-1
        // helper (per-element storeDynamic / array deep-copy, each OVERWRITE-CLEARING its old tail -
        // the same codec a whole `this.fixedArr = mem` assign uses, byte-identical to solc).
        const p = this.fresh();
        out.push(`let ${p} := mload(${at})`);
        this.storeDynLeafFixedArrayFromMem(f.type, p, fslotAt(f.slot), out);
      } else if (f.type.kind === 'struct' && isDynamicType(f.type)) {
        // W5C (family-wide): a NESTED DYNAMIC-STRUCT field: the head word holds the nested image's
        // absolute pointer; RECURSE into the nested struct's own field-by-field storage write at the
        // field's slot offset (each dynamic member overwrite-clears its old tail, exactly like solc's
        // member-wise struct assignment). Previously threw JETH900 for any nested-dyn-struct store.
        const p = this.fresh();
        out.push(`let ${p} := mload(${at})`);
        this.writeDynStructFromMem(f.type, p, fslotAt(f.slot), out);
      } else if (
        (f.type.kind === 'struct' || (f.type.kind === 'array' && f.type.length !== undefined)) &&
        isStaticType(f.type)
      ) {
        // W6A: a nested STATIC aggregate field (static struct / fixed value-array): its abiHeadWords
        // leaf words sit INLINE in the image at hw (the allocDynStructToMem tuple-head layout);
        // transcode them into the field's packed storage slots (the same codec writeStruct's
        // non-inline static-aggregate branch uses). Reachable since W6A passes memory dyn-struct
        // sources through to storage writes instead of desugaring them field-by-field.
        const p = this.fresh();
        out.push(`let ${p} := ${at}`);
        this.storeStaticAggFromMem(f.type, p, fslotAt(f.slot), out);
      } else {
        throw new UnsupportedError(
          `storing a struct with a '${f.type.kind}' field from a memory/calldata source is not supported yet`,
        );
      }
      hw += isDynamicType(f.type) ? 1 : abiHeadWords(f.type);
    }
  }

  /** Copy a STATIC aggregate (struct / fixed array of static elements) from an ABI-unpacked memory
   *  image (one word per leaf - the memAggregate / calldata-decoded layout) into PACKED storage.
   *  The inverse of abiEncFromStorage's static branch; storeState read-modify-writes each packed
   *  leaf, so leaves sharing a slot compose correctly and slot padding stays zero. */
  private storeStaticAggFromMem(t: JethType, memPtr: string, slot: string, out: string[]): void {
    // W6C: a fixed ENUM array image is range-checked before the packed store (Panic 0x21, solc's
    // memory->storage copy) - a bound memory local may hold RAW dirty words from the bind copy.
    this.validateEnumMemArray(t, memPtr, out);
    const sConst = /^\d+$/.test(slot);
    for (const leaf of structStorageLeaves(t)) {
      const ls =
        leaf.storageSlot === 0
          ? slot
          : sConst
            ? String(BigInt(slot) + BigInt(leaf.storageSlot))
            : `add(${slot}, ${leaf.storageSlot})`;
      const w = this.fresh();
      out.push(`let ${w} := mload(${leaf.abiWord === 0 ? memPtr : `add(${memPtr}, ${leaf.abiWord * 32})`})`);
      for (const l of this.storeState(leaf.type, ls, leaf.storageOffset, w)) out.push(l);
    }
  }

  private structSrcSlot(value: Expr, ctx: LowerCtx, out: string[]): string {
    if (value.kind === 'structValue') return String(value.baseSlot);
    if (value.kind === 'mapStorageValue') return this.mappingSlot(value.baseSlot, value.keys, ctx, out);
    if (value.kind === 'structArrayElem') return this.structArrayElemSlot(value.arr, value.index, ctx, out);
    if (value.kind === 'placeRead') return this.lowerPlace(value.path, ctx, out).slot;
    throw new UnsupportedError(`cannot copy a struct from '${value.kind}'`);
  }

  /** Storage-to-storage deep copy of a struct value from `srcBase` to `dstBase` (slot
   *  exprs: const-numeric string or register). Static value/fixed-array fields are
   *  copied slot-for-slot (packed slots deduped); each bytes/string field is re-stored
   *  via storeDynamic (reads the source value into memory, overwrite-clears the dst old
   *  tail, repopulates long-data slots), and nested structs recurse. Byte-identical to
   *  solc's field-by-field struct copy. Static and bytes/string fields occupy DISJOINT
   *  slots, so the field order is immaterial: a static slot-copy never clobbers a
   *  dynamic field's header, so storeDynamic always sees the dst's true old length when
   *  clearing (src and dst never alias except a harmless self-copy). */
  private copyStruct(struct: JethType & { kind: 'struct' }, srcBase: string, dstBase: string, out: string[]): void {
    const sConst = /^\d+$/.test(srcBase);
    const dConst = /^\d+$/.test(dstBase);
    const sAt = (n: number): string =>
      sConst ? String(BigInt(srcBase) + BigInt(n)) : n === 0 ? srcBase : `add(${srcBase}, ${n})`;
    const dAt = (n: number): string =>
      dConst ? String(BigInt(dstBase) + BigInt(n)) : n === 0 ? dstBase : `add(${dstBase}, ${n})`;
    const copied = new Set<number>();
    for (const f of struct.fields) {
      if (f.type.kind === 'struct') {
        this.copyStruct(f.type, sAt(f.slot), dAt(f.slot), out);
      } else if (isBytesLike(f.type)) {
        this.storeDynamic(dAt(f.slot), { src: 'storage', slot: sAt(f.slot) }, out);
      } else if (f.type.kind === 'array' && f.type.length === undefined) {
        // a DYNAMIC-array field (u256[], bytes[], u256[][], D[] ...): deep-copy the length word AND the
        // keccak(slot) data region, clearing the dst's freed tail on shrink (byte-identical to solc's
        // `this.field = arr`). A slot-for-slot copy would move only the length word (storageSlotCount is 1)
        // and leave the dst's old keccak data stale - a silent storage miscompile.
        this.copyArray(f.type.element, sAt(f.slot), dAt(f.slot), out);
      } else if (f.type.kind === 'array' && f.type.length !== undefined && isDynamicType(f.type)) {
        // a FIXED array with dynamic elements (Arr<string,N>, Arr<bytes,N>, Arr<T[],N>, Arr<D,N> with a
        // dyn field): per-element deep copy (each element's keccak data + tail clear), not a slot-for-slot
        // copy of the header footprint.
        this.copyFixedArray(f.type, sAt(f.slot), dAt(f.slot), out);
      } else {
        const n = storageSlotCount(f.type);
        for (let k = 0; k < n; k++) {
          if (copied.has(f.slot + k)) continue;
          copied.add(f.slot + k);
          out.push(`sstore(${dAt(f.slot + k)}, sload(${sAt(f.slot + k)}))`);
        }
      }
    }
  }

  /** pop a struct element: shrink length, then fully clear the element's slots. A DYNAMIC struct
   *  element is cleared through the SAME recursive delete `delete this.vals[i]` uses (deleteStruct):
   *  it frees each bytes/string field's keccak long-data, DEEP-clears each dynamic-array field
   *  (length word + keccak data region), recurses into nested structs, and zeroes value fields -
   *  so a later push() into the reused slot never resurrects stale data (byte-identical to solc's
   *  full per-element delete incl. raw slots). A fully-static element just zeroes its slot footprint. */
  private lowerStructPop(arr: ArrayExpr, ctx: LowerCtx, out: string[]): void {
    const ref = this.lowerArrayRef(arr, ctx, out);
    if (ref.src !== 'storage') throw new UnsupportedError('pop on a non-storage array');
    const struct = arr.elem as JethType & { kind: 'struct' };
    const slots = storageSlotCount(struct);
    const len = this.fresh();
    out.push(`let ${len} := sload(${ref.lenSlot})`);
    out.push(`if iszero(${len}) { ${this.panic()}(0x31) }`);
    const nl = this.fresh();
    out.push(`let ${nl} := sub(${len}, 1)`);
    out.push(`sstore(${ref.lenSlot}, ${nl})`);
    const dataBase = this.fresh();
    out.push(`let ${dataBase} := ${this.arrayDataSlotHelper()}(${ref.lenSlot})`);
    const base = this.fresh();
    out.push(`let ${base} := add(${dataBase}, mul(${nl}, ${slots}))`);
    if (isDynamicType(struct)) {
      // Recursive delete: frees keccak long-data of bytes/string fields AND the keccak data region
      // of dynamic-array fields (a shallow clearStructDyn missed the latter -> data resurrection).
      this.deleteStruct(struct, base, out);
    } else {
      for (let j = 0; j < slots; j++) out.push(`sstore(${j === 0 ? base : `add(${base}, ${j})`}, 0)`);
    }
  }

  /** `delete <storage location>`: reset to the type's zero value, matching solc. VALUE
   *  targets are lowered as `= 0` by the analyzer; this handles bytes/string (clearStr),
   *  struct/array (recursive footprint clear), and a whole mapping (no-op). */
  private lowerDelete(target: LValue, ctx: LowerCtx, out: string[]): void {
    switch (target.kind) {
      case 'local': {
        // delete a memory aggregate local: rebind it to a FRESH zeroed image (solc parity - an alias
        // keeps the old value). Fresh memory above the free pointer is zero-initialized in the EVM.
        const words = abiHeadWords(target.type);
        const p = this.fresh();
        out.push(`let ${p} := mload(0x40)`);
        out.push(`mstore(0x40, add(${p}, ${words * 32}))`);
        out.push(`${this.ctxLookup(ctx, target.varName)} := ${p}`);
        return;
      }
      case 'dynState':
        out.push(`${this.clearStr()}(${target.slot})`);
        return;
      case 'mapDynState':
        out.push(`${this.clearStr()}(${this.mappingSlot(target.baseSlot, target.keys, ctx, out)})`);
        return;
      case 'strArrayElem':
        out.push(`${this.clearStr()}(${this.strArrayElemSlot(target.arr, target.index, ctx, out)})`);
        return;
      case 'dynPlace':
        out.push(`${this.clearStr()}(${this.lowerPlace(target.path, ctx, out).slot})`);
        return;
      case 'state':
        if (target.type.kind === 'mapping') return; // delete on a whole mapping is a no-op
        this.deleteAgg(target.type, String(target.slot), out);
        return;
      case 'mapping':
        this.deleteAgg(target.type, this.mappingSlot(target.baseSlot, target.keys, ctx, out), out);
        return;
      case 'place':
        if (target.type.kind === 'mapping') return;
        this.deleteAgg(target.type, this.lowerPlace(target.path, ctx, out).slot, out);
        return;
      case 'arrayElem':
        this.deleteAgg(target.type, this.structArrayElemSlot(target.arr, target.index, ctx, out), out);
        return;
      default:
        throw new UnsupportedError(`delete of '${target.kind}' is not supported`);
    }
  }

  /** Recursively clear a storage aggregate's footprint to zero (delete semantics). */
  private deleteAgg(type: JethType, slot: string, out: string[]): void {
    if (isBytesLike(type)) {
      out.push(`${this.clearStr()}(${slot})`);
      return;
    }
    if (type.kind === 'mapping') return; // mappings are not cleared by delete
    if (type.kind === 'array') {
      if (type.length === undefined) this.deleteDynArray(type.element, slot, out);
      else this.deleteFixedArray(type, slot, out);
      return;
    }
    if (type.kind === 'struct') {
      this.deleteStruct(type, slot, out);
      return;
    }
    out.push(`sstore(${slot}, 0)`); // whole-slot value fallback
  }

  /** Clear a storage struct: zero each value field (packed-aware), clear bytes/string and
   *  nested struct/array fields, and SKIP mapping fields (solc's delete leaves mappings). */
  private deleteStruct(struct: JethType & { kind: 'struct' }, base: string, out: string[]): void {
    const isConst = /^\d+$/.test(base);
    const at = (n: number): string =>
      isConst ? String(BigInt(base) + BigInt(n)) : n === 0 ? base : `add(${base}, ${n})`;
    for (const f of struct.fields) {
      if (f.type.kind === 'mapping') continue;
      if (isBytesLike(f.type)) out.push(`${this.clearStr()}(${at(f.slot)})`);
      else if (f.type.kind === 'struct' || f.type.kind === 'array') this.deleteAgg(f.type, at(f.slot), out);
      else for (const l of this.storeState(f.type, at(f.slot), f.offset, '0')) out.push(l);
    }
  }

  /** Clear a fixed array Arr<T,N>: a static VALUE / value-array element zeroes the whole
   *  (packed) footprint; struct / bytes-string / dynamic elements clear per element. */
  private deleteFixedArray(arrType: JethType & { kind: 'array' }, base: string, out: string[]): void {
    const elem = arrType.element;
    const N = arrType.length!;
    const isConst = /^\d+$/.test(base);
    const at = (n: number): string =>
      isConst ? String(BigInt(base) + BigInt(n)) : n === 0 ? base : `add(${base}, ${n})`;
    if (isStaticType(elem) && elem.kind !== 'struct') {
      const packs = arrayElemPacks(elem);
      const slots = packs.packed ? Math.ceil(N / packs.perSlot) : N * storageSlotCount(elem);
      for (let i = 0; i < slots; i++) out.push(`sstore(${at(i)}, 0)`);
      return;
    }
    const sc = storageSlotCount(elem);
    for (let i = 0; i < N; i++) this.deleteAgg(elem, at(i * sc), out);
  }

  /** Clear a dynamic array T[]: free/zero every element's slots then set length 0. Mirrors
   *  copyArray's shrink-to-zero (static value elements zero the used data slots; struct /
   *  bytes-string / nested-array elements recurse per element). */
  private deleteDynArray(elem: JethType, lenSlot: string, out: string[]): void {
    const len = this.fresh();
    out.push(`let ${len} := sload(${lenSlot})`);
    const data = this.fresh();
    out.push(`let ${data} := ${this.arrayDataSlotHelper()}(${lenSlot})`);
    if (isStaticType(elem) && elem.kind !== 'struct') {
      const packs = arrayElemPacks(elem);
      const slots = this.fresh();
      out.push(
        `let ${slots} := ${packs.packed ? `div(add(${len}, ${packs.perSlot - 1}), ${packs.perSlot})` : `mul(${len}, ${storageSlotCount(elem)})`}`,
      );
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${slots}) { ${i} := add(${i}, 1) } { sstore(add(${data}, ${i}), 0) }`);
    } else {
      const sc = storageSlotCount(elem);
      const k = this.fresh();
      out.push(`for { let ${k} := 0 } lt(${k}, ${len}) { ${k} := add(${k}, 1) } {`);
      const inner: string[] = [];
      const eb = this.fresh();
      inner.push(`let ${eb} := add(${data}, mul(${k}, ${sc}))`);
      this.deleteAgg(elem, eb, inner);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
    }
    out.push(`sstore(${lenSlot}, 0)`);
  }

  // ---- storage / mapping-valued string[] / bytes[] (element = a storage bytes/
  // string at header slot keccak(lenSlot)+i; reuse the storage bytes/string codec)

  /** push a bytes/string element: grow the length word (Panic 0x41 past 2^64-1),
   *  then write the element header at keccak(lenSlot)+old_len via storeStrMem (short
   *  inline / long with keccak(headerSlot) data slots). A no-value push leaves the
   *  freed slot zero (an empty string = the 0 length word), so it is a no-op write. */
  private lowerStrPush(arr: ArrayExpr, value: Expr | undefined, ctx: LowerCtx, out: string[]): void {
    const ref = this.lowerArrayRef(arr, ctx, out);
    if (ref.src !== 'storage') throw new UnsupportedError('push on a non-storage array');
    // W7B (arg-first): resolve the pushed VALUE's reference BEFORE the grow - solc evaluates the
    // argument first, so strs.push(strs[0]) on an empty array panics on the source bounds check
    // (P11) instead of aliasing the freshly-grown empty element. The copy itself reads the source
    // after the grow, matching solc (the grown region never overlaps a valid source).
    const vref = value ? this.lowerDynamic(value, ctx, out) : undefined;
    const len = this.fresh();
    out.push(`let ${len} := sload(${ref.lenSlot})`);
    out.push(`if gt(${len}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
    out.push(`sstore(${ref.lenSlot}, add(${len}, 1))`);
    const dataBase = this.arrayDataSlot(ref.lenSlot, out);
    const hdr = this.fresh();
    out.push(`let ${hdr} := add(${dataBase}, ${len})`);
    if (vref) {
      this.storeDynamic(hdr, vref, out); // header slot was zero (grown fresh), no old tail to clear
    }
    // push() with no value: the element is the storage default (empty), already 0.
  }

  /** pop a bytes/string element: shrink the length word (Panic 0x31 if empty), then
   *  clear the freed element's header AND its tail data slots (a long element's
   *  keccak(headerSlot) data slots), matching solc's full clear. storeStrMem with
   *  len 0 sets the header to the 0 length word and zeroes the old data slots. */
  private lowerStrPop(arr: ArrayExpr, ctx: LowerCtx, out: string[]): void {
    const ref = this.lowerArrayRef(arr, ctx, out);
    if (ref.src !== 'storage') throw new UnsupportedError('pop on a non-storage array');
    const len = this.fresh();
    out.push(`let ${len} := sload(${ref.lenSlot})`);
    out.push(`if iszero(${len}) { ${this.panic()}(0x31) }`);
    const nl = this.fresh();
    out.push(`let ${nl} := sub(${len}, 1)`);
    out.push(`sstore(${ref.lenSlot}, ${nl})`);
    const dataBase = this.arrayDataSlot(ref.lenSlot, out);
    const hdr = this.fresh();
    out.push(`let ${hdr} := add(${dataBase}, ${nl})`);
    out.push(`${this.clearStr()}(${hdr})`);
  }

  /** Resolve a storage `bytes` LOCATION lvalue (a direct state var, a struct field, a mapping value,
   *  or a bytes[]/Arr<bytes,N> element) to its header slot, using the SAME resolver each whole-value
   *  assignment uses, so a .push/.pop/b[i]=x mutation lands on the identical slot. */
  private bytesLocSlot(loc: LValue, ctx: LowerCtx, out: string[]): string {
    switch (loc.kind) {
      case 'dynState':
        return String(loc.slot);
      case 'mapDynState':
        return this.mappingSlot(loc.baseSlot, loc.keys, ctx, out);
      case 'strArrayElem':
        return this.strArrayElemSlot(loc.arr, loc.index, ctx, out);
      case 'dynPlace':
        return this.lowerPlace(loc.path, ctx, out).slot;
      default:
        throw new UnsupportedError(`bytes mutation through a '${loc.kind}' location is not supported`);
    }
  }

  /** Storage header slot of bytes/string element `i` of a storage string[]/bytes[].
   *  Bounds-checks i against the array length (Panic 0x32), then returns
   *  keccak(lenSlot)+i. The header is a normal storage bytes/string. */
  private strArrayElemSlot(arr: ArrayExpr, index: Expr, ctx: LowerCtx, out: string[], oobEmpty = false): string {
    const ref = this.lowerArrayRef(arr, ctx, out);
    const i = this.fresh();
    out.push(`let ${i} := ${this.lowerExpr(index, ctx, out)}`);
    // @public getters revert EMPTY on out-of-bounds (solc parity); ordinary access Panics 0x32.
    const oob = oobEmpty ? 'revert(0, 0)' : `${this.panic()}(0x32)`;
    // Arr<string,N>/Arr<bytes,N> (fixed): N contiguous string headers at baseSlot + i.
    if (ref.src === 'fixed') {
      out.push(`if iszero(lt(${i}, ${ref.length})) { ${oob} }`);
      const hdr = this.fresh();
      out.push(`let ${hdr} := add(${ref.baseSlot}, ${i})`);
      return hdr;
    }
    if (ref.src !== 'storage') throw new UnsupportedError('string[]/bytes[] element requires a storage array');
    out.push(`if iszero(lt(${i}, sload(${ref.lenSlot}))) { ${oob} }`);
    const dataBase = this.arrayDataSlot(ref.lenSlot, out);
    const hdr = this.fresh();
    out.push(`let ${hdr} := add(${dataBase}, ${i})`);
    return hdr;
  }

  /** ABI-encode a MEMORY value-array at pointer `mp` (=[len][data]) as [0x20][len][data]. */
  private encodeMemArrayReturn(mp: string, out: string[], t?: JethType): { ptr: string; size: string } {
    // W6C: encoding a memory ENUM array to returndata range-checks every element (Panic 0x21,
    // solc's validator_assert) - the image may hold RAW dirty words from a calldata bind copy.
    if (t !== undefined) this.validateEnumMemArray(t, mp, out);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`);
    const total = this.fresh();
    out.push(`let ${total} := mul(add(mload(${mp}), 1), 0x20)`);
    out.push(`mcopy(add(${ptr}, 0x20), ${mp}, ${total})`);
    out.push(`mstore(0x40, add(add(${ptr}, 0x20), ${total}))`);
    return { ptr, size: `add(0x20, ${total})` };
  }

  /** Resolve a NESTED value-array value expression to its memory-image pointer (JETH's nested
   *  representation, the input abiEncFromMem reads). Sources: an array literal / new Array builds a
   *  fresh image; a memory-array local / fixed-array aggregate local / nested element / ternary
   *  ALIASES its pointer. */
  private nestedMemImagePtr(value: Expr, ctx: LowerCtx, out: string[]): string {
    if (value.kind === 'arrayLit') {
      // Batch A: a STATIC fixed-outer static-struct array literal (Arr<P,N>) is POINTER-HEADED (N pointer
      // words -> fresh per-element images), built by the nested codec - NOT the inline allocAggToMem image.
      if (isDynamicType(value.type) || isStaticStructFixedLeafArray(value.type))
        return this.buildNestedMemArrayLit(value, ctx, out);
      return this.allocAggToMem(value, ctx, out); // a static nested VALUE literal: inline image
    }
    if (value.kind === 'newArray') return this.lowerExpr(value, ctx, out);
    if (value.kind === 'memAggregate') return this.lowerExpr(value, ctx, out);
    if (value.kind === 'arrayValue') {
      const b = value.arr.base;
      if (b.kind === 'memArray') return this.ctxLookup(ctx, b.varName);
      if (b.kind === 'memArrayExpr') {
        const p = this.fresh();
        out.push(`let ${p} := ${this.lowerExpr(b.expr, ctx, out)}`);
        return p;
      }
      // cd-to-mem-copy: a whole REFERENCE-element calldata array used as a constructor leaf-array field
      // (P(7n, t) where t is bytes[]/string[]/u256[][] calldata) DEEP-COPIES into a fresh pointer-headed
      // memory image via abiDecFromCdToImage. The param's [len] word is one word before its table base
      // (cdArrays.offset = the word AFTER [len]). solc's calldata->memory copy hits the MEMORY allocation
      // guard (Panic 0x41) on an oversized inner length / alloc overflow, so pass that cap.
      if (b.kind === 'calldataArray' && value.type.kind === 'array' && !isStaticValueType(value.type.element)) {
        const cd = ctx.cdArrays.get(b.name);
        if (!cd) throw new UnsupportedError(`calldata array '${b.name}' is not registered`);
        return this.abiDecFromCdToImage(value.type, `sub(${cd.offset}, 0x20)`, out, `${this.panic()}(0x41)`);
      }
    }
    // a whole DYNAMIC-ARRAY field of a calldata dyn-struct array element (xs[i].grid / xs[i].items) used
    // as an abi.encode arg / a memory-image source: DEEP-COPY it from its resolved calldata header into a
    // fresh pointer-headed memory image. cap = Panic(0x41), matching solc's calldata->memory deep copy.
    if (value.kind === 'cdFieldAggValue') {
      const hdr = this.cdFieldArrayHeader(value.place, ctx, out);
      return this.abiDecFromCdToImage(value.type, hdr, out, `${this.panic()}(0x41)`);
    }
    if (value.kind === 'cdNestedFieldAggValue') {
      const hdr = this.cdNestedFieldArrayHeader(value.place, value.indices, ctx, out);
      return this.abiDecFromCdToImage(value.type, hdr, out, `${this.panic()}(0x41)`);
    }
    const p = this.fresh();
    out.push(`let ${p} := ${this.lowerExpr(value, ctx, out)}`);
    return p;
  }

  /** ABI-encode a NESTED value-array memory image at `mp` (type `t`) into a fresh return blob. A
   *  type with a DYNAMIC level gets the leading [0x20] offset wrapper (it is a dynamic top-level
   *  return); abiEncFromMem writes the inner [len]/offset-table/tails. Returns {ptr, size}. */
  private encodeNestedMemReturn(t: JethType, mp: string, ctx: LowerCtx, out: string[]): { ptr: string; size: string } {
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`);
    const size = this.fresh();
    out.push(`let ${size} := ${this.abiEncFromMem(t, mp, `add(${ptr}, 0x20)`, ctx, out)}`);
    out.push(`mstore(0x40, add(add(${ptr}, 0x20), ${size}))`);
    return { ptr, size: `add(0x20, ${size})` };
  }

  // ---- zero-value encoding (solc `zero_value_for_type`) --------------------
  // Shared, structural encoders for the ZERO value of a return type, used on SKIP / FALL-THROUGH
  // paths (an internal function that runs off its end, a modifier whose placeholder never fires, an
  // external function whose only `return` is guarded). solc returns the ABI encoding of the type's
  // zero value; JETH previously read uninitialized memory (keccak scratch / free-mem-ptr) or emitted
  // a dynamic [0x20][0] blob for a STATIC aggregate, leaking attacker-influenceable mapping keys /
  // lengths (P0-3 / P0-4 / P0-12). All zero-blob sizes are compile-time constants.

  /** Write the ABI encoding of a zero value of `t` (as a TAIL, no top-level wrapper) at memory `dst`.
   *  Returns the byte size (a compile-time constant). Actively zeroes every word (calldatacopy from
   *  past calldatasize writes zeros - solc's zero-init idiom), so the result is all-zero over dirty
   *  memory, then overwrites the offset words of any dynamic sub-parts. */
  private zeroAbiInto(t: JethType, dst: string, out: string[]): number {
    if (isStaticType(t)) {
      const sz = abiHeadWords(t) * 32;
      out.push(`calldatacopy(${dst}, calldatasize(), ${sz})`);
      return sz;
    }
    if (isBytesLike(t) || (t.kind === 'array' && t.length === undefined)) {
      out.push(`mstore(${dst}, 0)`); // [len=0]
      return 32;
    }
    if (t.kind === 'struct') return this.zeroAbiTuple(t.fields.map((f) => f.type), dst, out);
    if (t.kind === 'array' && t.length !== undefined)
      return this.zeroAbiTuple(Array.from({ length: t.length }, () => t.element), dst, out); // fixed-of-dynamic
    throw new UnsupportedError(`zero value for type '${t.kind}' is not supported`);
  }

  /** Write a zero ABI TUPLE (components `types`) at `dst`, returns the byte size. A static component
   *  occupies its abiHeadWords inline zero words; a dynamic component occupies one head offset word
   *  (pointing at its tail) then its zero tail after the head run. Reused for a multi-value return, a
   *  dynamic struct's fields, and a fixed-of-dynamic array's N elements. */
  private zeroAbiTuple(types: JethType[], dst: string, out: string[]): number {
    const headWords = types.reduce((n, c) => n + (isDynamicType(c) ? 1 : abiHeadWords(c)), 0);
    const headBytes = headWords * 32;
    // Zero the whole head run first (static components stay zero; dynamic components get their offset
    // word overwritten below).
    out.push(`calldatacopy(${dst}, calldatasize(), ${headBytes})`);
    let headOff = 0;
    let cursor = headBytes;
    for (const c of types) {
      if (isDynamicType(c)) {
        out.push(`mstore(add(${dst}, ${headOff}), ${cursor})`); // relative offset to this component's tail
        cursor += this.zeroAbiInto(c, `add(${dst}, ${cursor})`, out);
        headOff += 32;
      } else {
        headOff += abiHeadWords(c) * 32;
      }
    }
    return cursor;
  }

  /** Build the full ABI zero-return blob for a SINGLE return value of type `t`, returning {ptr, size}.
   *  A dynamic type gets the leading [0x20] top-level offset wrapper (a dynamic array / bytes / string
   *  / dynamic struct is a dynamic top-level return); a static type is returned inline. */
  private encodeZeroReturnSingle(t: JethType, out: string[]): { ptr: string; size: string } {
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    if (isDynamicType(t)) {
      out.push(`mstore(${ptr}, 0x20)`);
      const sz = this.zeroAbiInto(t, `add(${ptr}, 0x20)`, out);
      const total = 0x20 + sz;
      out.push(`mstore(0x40, add(${ptr}, ${total}))`);
      return { ptr, size: String(total) };
    }
    const sz = this.zeroAbiInto(t, ptr, out);
    out.push(`mstore(0x40, add(${ptr}, ${sz}))`);
    return { ptr, size: String(sz) };
  }

  /** Build the full ABI zero-return blob for a MULTI-VALUE return (`types`), returning {ptr, size}. A
   *  multi-value return is a bare tuple (NO leading top-level offset wrapper); dynamic components are
   *  offset-encoded within the tuple. */
  private encodeZeroReturnMulti(types: JethType[], out: string[]): { ptr: string; size: string } {
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    const sz = this.zeroAbiTuple(types, ptr, out);
    out.push(`mstore(0x40, add(${ptr}, ${sz}))`);
    return { ptr, size: String(sz) };
  }

  /** Build a fresh ZERO memory image (JETH's internal representation, what aggArgToMemPtr produces) for
   *  an aggregate / bytes / string type `t`, returning its pointer. Used to initialize an internal
   *  function's aggregate return var (P0-3) and to bind a modifier's buffered aggregate return var
   *  (P0-4) on a 0-times / early-exit path, so the shared return encoder re-encodes solc's zero value
   *  instead of reading uninitialized memory. Layout matches what the corresponding `return <value>`
   *  path materializes (a static struct/array = flat inline zero words; a dynamic array / bytes / string
   *  = [len=0]; a dynamic struct = pointer-headed head with dynamic-field pointers to empty sentinels;
   *  a fixed-of-dynamic / pointer-headed static-struct array = N pointers to fresh zero element images). */
  private zeroImageFor(t: JethType, ctx: LowerCtx, out: string[]): string {
    // bytes / string: a fresh empty [len=0] blob.
    if (isBytesLike(t)) {
      const p = this.fresh();
      out.push(`let ${p} := mload(0x40)`);
      out.push(`mstore(${p}, 0)`);
      out.push(`mstore(0x40, add(${p}, 0x20))`);
      return p;
    }
    // a STATIC aggregate that is NOT pointer-headed (a flat static struct / static value array): the
    // image IS its abiHeadWords inline zero words (the same flat blob allocAggToMem produces).
    if (isStaticType(t) && !(t.kind === 'array' && isStaticStructFixedLeafArray(t))) {
      const hw = abiHeadWords(t);
      const p = this.fresh();
      out.push(`let ${p} := mload(0x40)`);
      out.push(`calldatacopy(${p}, calldatasize(), ${hw * 32})`);
      out.push(`mstore(0x40, add(${p}, ${hw * 32}))`);
      return p;
    }
    // a DYNAMIC-field struct: the pointer-headed zero image (value fields 0; each dynamic field's head
    // word points at a fresh empty [len=0] sentinel).
    if (t.kind === 'struct') return this.emptyDynStructImage(t, out);
    // a DYNAMIC array T[] (len 0): a single [len=0] word (abiEncFromMem reads len=0 and emits no tail).
    if (t.kind === 'array' && t.length === undefined) {
      const p = this.fresh();
      out.push(`let ${p} := mload(0x40)`);
      out.push(`mstore(${p}, 0)`);
      out.push(`mstore(0x40, add(${p}, 0x20))`);
      return p;
    }
    // a FIXED-outer pointer-headed array (Arr<u256[],N> fixed-of-dynamic, Arr<P,N> static-struct-leaf,
    // Arr<bytes,N>): N absolute-pointer words, each -> a fresh zero element image (recursive).
    if (t.kind === 'array' && t.length !== undefined) {
      const n = t.length;
      const p = this.fresh();
      out.push(`let ${p} := mload(0x40)`);
      out.push(`mstore(0x40, add(${p}, ${n * 32}))`);
      for (let k = 0; k < n; k++) {
        const ip = this.zeroImageFor(t.element, ctx, out);
        out.push(`mstore(add(${p}, ${k * 32}), ${ip})`);
      }
      return p;
    }
    throw new UnsupportedError(`zero image for type '${t.kind}' is not supported`);
  }

  /** Encode an arrayValue/arrayLit as ABI [0x20][len][elem words...] in memory. */
  private encodeArrayReturn(value: Expr, ctx: LowerCtx, out: string[]): { ptr: string; size: string } {
    if (value.kind === 'arrayLit') {
      const ws = value.elements.map((el) => this.lowerExpr(el, ctx, out));
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      out.push(`mstore(${ptr}, 0x20)`, `mstore(add(${ptr}, 0x20), ${ws.length})`);
      ws.forEach((w, j) => out.push(`mstore(add(${ptr}, ${0x40 + j * 32}), ${w})`));
      out.push(`mstore(0x40, add(${ptr}, ${0x40 + ws.length * 32}))`);
      return { ptr, size: String(0x40 + ws.length * 32) };
    }
    if (value.kind === 'newArray') {
      // new Array<T>(n) lowers to a [len][data] memory pointer; encode it as a dynamic memory array.
      const p = this.fresh();
      out.push(`let ${p} := ${this.lowerExpr(value, ctx, out)}`);
      return this.encodeMemArrayReturn(p, out, value.type);
    }
    if (value.kind !== 'arrayValue') throw new UnsupportedError(`cannot encode array from ${value.kind}`);
    // a MEMORY T[] (value elements) at ptr=[len][data]: ABI return = [0x20][len][data].
    if (value.arr.base.kind === 'memArray') {
      return this.encodeMemArrayReturn(this.ctxLookup(ctx, value.arr.base.varName), out, value.type);
    }
    // a memory T[] produced by an expression (a dynamic-array ternary `c ? this.a : this.b`):
    // lower to the [len][elems] pointer (freeze first), then encode.
    if (value.arr.base.kind === 'memArrayExpr') {
      const p = this.fresh();
      out.push(`let ${p} := ${this.lowerExpr(value.arr.base.expr, ctx, out)}`);
      return this.encodeMemArrayReturn(p, out, value.type);
    }
    const ref = this.lowerArrayRef(value.arr, ctx, out);
    if (ref.src === 'fixed') throw new UnsupportedError('returning a whole fixed array is not supported yet');
    if (ref.src === 'memory') throw new UnsupportedError('memory array return is handled earlier');
    // string[] / bytes[] (array of dynamic elements): re-encode each element as a
    // [byteLen][right-padded data] payload behind a per-element offset table whose
    // base is the table start (spec section 4.1). Only the calldata-source path is
    // reachable (the analyzer gates storage/mapping string[] elements).
    if (isBytesLike(ref.elem)) {
      if (ref.src !== 'calldata')
        throw new UnsupportedError('returning a string[]/bytes[] is only supported from a calldata source');
      return this.encodeDynArrayReturn(ref.offset, ref.length, ctx, out);
    }
    // Nested dynamic array T[][] (4e-5): re-encode each inner array as a [innerLen]
    // [elements] tail behind a per-inner pointer table whose base is the pointer-region
    // start (spec section 2.1). Only the calldata-source path is reachable.
    if (ref.elem.kind === 'array' && ref.elem.length === undefined) {
      if (ref.src !== 'calldata')
        throw new UnsupportedError('returning a nested dynamic array is only supported from a calldata source');
      return this.encodeNestedArrayReturn(ref.offset, ref.length, ref.elem.element, ctx, out);
    }
    // a STORAGE D[] whose element struct D is itself DYNAMIC (a bytes/string/dynamic-array/nested-
    // dynamic-leaf field): the element is NOT byte-invariant, so the static-inline transcode below
    // (a fixed abiHeadWords(elem)*32 stride) emits garbage. Encode head/tail (a per-element offset
    // table + per-element dynamic encoding) via the recursive storage->ABI encoder - the SAME path
    // `return this.s` uses for a single dynamic struct, proven byte-identical to solc. Wrap with the
    // sole-return [0x20] offset.
    if (ref.src === 'storage' && ref.elem.kind === 'struct' && isDynamicType(ref.elem)) {
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      out.push(`mstore(${ptr}, 0x20)`);
      const arrType: JethType = { kind: 'array', element: ref.elem, length: undefined };
      const size = this.fresh();
      out.push(`let ${size} := ${this.abiEncFromStorage(arrType, ref.lenSlot, 0, `add(${ptr}, 0x20)`, out)}`);
      out.push(`mstore(0x40, add(add(${ptr}, 0x20), ${size}))`);
      return { ptr, size: `add(0x20, ${size})` };
    }
    const len = this.fresh();
    out.push(`let ${len} := ${ref.src === 'storage' ? `sload(${ref.lenSlot})` : ref.length}`);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`, `mstore(add(${ptr}, 0x20), ${len})`);
    const e = this.fresh();
    out.push(`let ${e} := add(${ptr}, 0x40)`);
    const i = this.fresh();
    const inner: string[] = [];
    let stride: string;
    if (ref.src === 'storage') {
      const data = this.arrayDataSlot(ref.lenSlot, out);
      if (ref.elem.kind === 'struct') {
        // transcode each packed storage struct element to its unpacked ABI words.
        const sw = abiHeadWords(ref.elem) * 32;
        const sc = storageSlotCount(ref.elem);
        stride = String(sw);
        const eb = this.fresh();
        inner.push(`let ${eb} := add(${data}, mul(${i}, ${sc}))`);
        for (const leaf of structStorageLeaves(ref.elem)) {
          const slotExpr = leaf.storageSlot === 0 ? eb : `add(${eb}, ${leaf.storageSlot})`;
          const w = this.loadState(leaf.type, slotExpr, leaf.storageOffset);
          const dst = leaf.abiWord === 0 ? `mul(${i}, ${sw})` : `add(mul(${i}, ${sw}), ${leaf.abiWord * 32})`;
          inner.push(`mstore(add(${e}, ${dst}), ${w})`);
        }
      } else {
        // value element: one ABI word per element (unpacked by arrayElemLoad).
        stride = '32';
        inner.push(`mstore(add(${e}, mul(${i}, 32)), ${this.arrayElemLoad(ref.elem, data, i)})`);
      }
    } else {
      // calldata source. A VALUE-element whole-array copy CLEANS each element (does
      // NOT revert on dirty bits), unlike a single x[i] read (Bug-A behavior). A
      // STRUCT-element copy instead reads every field, so it VALIDATES each leaf
      // (revert empty on dirty), matching solc - it never cleans struct fields.
      const sw = abiHeadWords(ref.elem) * 32;
      stride = String(sw);
      const elemIsStruct = ref.elem.kind === 'struct';
      for (const leaf of abiLeaves(ref.elem)) {
        const disp = leaf.wordOffset * 32;
        const at = disp === 0 ? `mul(${i}, ${sw})` : `add(mul(${i}, ${sw}), ${disp})`;
        const w = this.fresh();
        inner.push(`let ${w} := calldataload(add(${ref.offset}, ${at}))`);
        if (elemIsStruct) {
          const guard = this.validateInput(leaf.type, w);
          if (guard) inner.push(guard);
          inner.push(`mstore(add(${e}, ${at}), ${w})`);
        } else if (this.enumCount(leaf.type) !== undefined) {
          // W6C: an ENUM leaf in a calldata-source array RETURN re-encode (`return a.slice(s)`,
          // `return d.tags`) is range-checked with Panic(0x21) - solc's abi_encode validator_assert
          // - NOT masked (masking silently returned dirty words: a wrong-bytes miscompile).
          inner.push(`if iszero(lt(${w}, ${this.enumCount(leaf.type)})) { ${this.panic()}(0x21) }`);
          inner.push(`mstore(add(${e}, ${at}), ${w})`);
        } else {
          inner.push(`mstore(add(${e}, ${at}), ${this.cleanCalldataElem(leaf.type, w)})`);
        }
      }
    }
    out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
    for (const l of inner) out.push('  ' + l);
    out.push('}');
    out.push(`mstore(0x40, add(${e}, mul(${len}, ${stride})))`);
    return { ptr, size: `add(0x40, mul(${len}, ${stride}))` };
  }

  /** Re-encode a calldata string[]/bytes[] (table start `tableStart`, element count
   *  `len`) into memory as the ABI return blob: [0x20][len][offset table][payloads].
   *  Each payload is [byteLen][right-padded data]; the offset table base is the table
   *  start (spec section 4.1). Element bounds are validated per element on decode.
   *  The total byte size is computed at runtime (variable payload lengths). */
  private encodeDynArrayReturn(
    tableStart: string,
    len: string,
    ctx: LowerCtx,
    out: string[],
  ): { ptr: string; size: string } {
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`); // outer offset
    const region = this.fresh();
    out.push(`let ${region} := add(${ptr}, 0x20)`); // array data region start
    out.push(`mstore(${region}, ${len})`); // element count
    const table = this.fresh();
    out.push(`let ${table} := add(${region}, 0x20)`); // output offset-table start (= base)
    // payload cursor starts right after the L offset-table words.
    const cursor = this.fresh();
    out.push(`let ${cursor} := add(${table}, mul(${len}, 0x20))`);
    const i = this.fresh();
    out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
    const inner: string[] = [];
    const dataPtr = this.fresh();
    const elen = this.fresh();
    inner.push(`let ${dataPtr}, ${elen} := ${this.calldataDynElemEcho()}(${tableStart}, ${i})`);
    // offset of this element's payload relative to the output table start.
    inner.push(`mstore(add(${table}, mul(${i}, 0x20)), sub(${cursor}, ${table}))`);
    // DECODE-TO-MEMORY ECHO alloc bound (rule 3): a byte payload first caps the length
    // at 2^64-1 (Panic 0x41, so roundup32 cannot wrap), then the new free pointer
    // (cursor past this payload) crossing 2^64-1 (or wrapping) -> Panic(0x41); THEN the
    // payload must lie within calldatasize (else EMPTY). All precede the copy/store.
    inner.push(`if gt(${elen}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
    const pad = `and(add(${elen}, 0x1f), not(0x1f))`;
    const nc = this.fresh();
    inner.push(`let ${nc} := add(${cursor}, add(0x20, ${pad}))`);
    inner.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${cursor})) { ${this.panic()}(0x41) }`);
    inner.push(`if gt(add(${dataPtr}, ${elen}), calldatasize()) { revert(0, 0) }`);
    inner.push(`mstore(${cursor}, ${elen})`); // byte length word
    // copy payload then zero the partial-word tail so padding is clean.
    inner.push(`calldatacopy(add(${cursor}, 0x20), ${dataPtr}, ${elen})`);
    inner.push(`if mod(${elen}, 0x20) { mstore(add(add(${cursor}, 0x20), ${elen}), 0) }`);
    inner.push(`${cursor} := ${nc}`);
    for (const l of inner) out.push('  ' + l);
    out.push('}');
    out.push(`mstore(0x40, ${cursor})`); // bump free-mem pointer past the blob
    return { ptr, size: `sub(${cursor}, ${ptr})` };
  }

  /** Re-encode a calldata nested dynamic array T[][] (pointer-region start `base`,
   *  outer count `len`, value element `elemType`) into memory as the ABI return blob:
   *  [0x20][outerLen][pointer table][inner tails]. Each inner tail is [innerLen][elem
   *  words...]; the pointer offsets are relative to the output pointer-region start
   *  (= the output table start), spec section 2.1. Each value element is CLEANED into
   *  its in-register form on copy (does not revert on dirty bits), matching solc's
   *  array-copy semantics for value elements. Inner bounds / pointer faults -> EMPTY
   *  revert inside calldataInnerArray. Total byte size is computed at runtime. */
  private encodeNestedArrayReturn(
    base: string,
    len: string,
    elemType: JethType,
    ctx: LowerCtx,
    out: string[],
  ): { ptr: string; size: string } {
    const stride = abiHeadWords(elemType) * 32; // value element stride (32)
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`); // outer offset
    const region = this.fresh();
    out.push(`let ${region} := add(${ptr}, 0x20)`); // outer data region start
    out.push(`mstore(${region}, ${len})`); // outer element count
    const table = this.fresh();
    out.push(`let ${table} := add(${region}, 0x20)`); // output pointer-region start (= base)
    // inner-tail cursor starts right after the L pointer words.
    const cursor = this.fresh();
    out.push(`let ${cursor} := add(${table}, mul(${len}, 0x20))`);
    const i = this.fresh();
    out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
    const inner: string[] = [];
    const dataOff = this.fresh();
    const innerLen = this.fresh();
    inner.push(`let ${dataOff}, ${innerLen} := ${this.calldataInnerArrayEcho()}(${base}, ${i})`);
    // pointer to this inner array, relative to the output table start.
    inner.push(`mstore(add(${table}, mul(${i}, 0x20)), sub(${cursor}, ${table}))`);
    // DECODE-TO-MEMORY ECHO alloc bound (rule 3): a memory value-array first caps the
    // element count at 2^64-1 (Panic 0x41), then the new free pointer (cursor past this
    // inner tail) crossing 2^64-1 (or wrapping) -> Panic(0x41). Both precede any element
    // read/validation, matching solc's allocate-then-decode ordering.
    inner.push(`if gt(${innerLen}, 0xffffffffffffffff) { ${this.panic()}(0x41) }`);
    const nc = this.fresh();
    inner.push(`let ${nc} := add(${cursor}, add(0x20, mul(${innerLen}, 0x20)))`);
    inner.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${cursor})) { ${this.panic()}(0x41) }`);
    // payload-fits (after the alloc Panic, EMPTY): the innerLen element words must lie
    // within calldatasize, else solc's memory decode reverts EMPTY (measured).
    inner.push(`if gt(add(${dataOff}, mul(${innerLen}, ${stride})), calldatasize()) { revert(0, 0) }`);
    inner.push(`mstore(${cursor}, ${innerLen})`); // inner length word
    // copy each inner element, cleaned into in-register form.
    const j = this.fresh();
    const ew = this.fresh();
    inner.push(`for { let ${j} := 0 } lt(${j}, ${innerLen}) { ${j} := add(${j}, 1) } {`);
    inner.push(`  let ${ew} := calldataload(add(${dataOff}, mul(${j}, ${stride})))`);
    // solc fully decodes each inner array and VALIDATES every element (a dirty
    // narrow value reverts EMPTY), unlike a flat value-array bulk copy which cleans.
    const guard = this.validateInput(elemType, ew);
    if (guard) inner.push(`  ${guard}`);
    inner.push(`  mstore(add(add(${cursor}, 0x20), mul(${j}, 0x20)), ${ew})`);
    inner.push(`}`);
    inner.push(`${cursor} := ${nc}`);
    for (const l of inner) out.push('  ' + l);
    out.push('}');
    out.push(`mstore(0x40, ${cursor})`); // bump free-mem pointer past the blob
    return { ptr, size: `sub(${cursor}, ${ptr})` };
  }

  /** Echo a whole calldata PARAM `name` of dynamic type `t` into a fresh ABI return
   *  blob: [0x20][value encoding]. The general recursive encoder gives UNBOUNDED
   *  nesting depth. The top-level offset is signed-range-checked (solc form). */
  private echoParam(
    name: string,
    t: JethType,
    ctx: LowerCtx,
    out: string[],
    forceValidate = false,
    // W6C: the calldata->memory BIND copy context (`const b: Color[] = a` / internal-call arg):
    // enum words copy RAW (no eager Panic 0x21) - solc's convert-to-memory is a raw calldatacopy
    // and validates lazily at the element read. The RETURN echo keeps the eager Panic.
    enumRaw = false,
  ): { ptr: string; size: string } {
    const ph = ctx.cdParamHead.get(name);
    if (!ph) throw new UnsupportedError(`unbound echo param ${name}`);
    const off = this.fresh();
    out.push(`let ${off} := calldataload(${ph.head})`);
    out.push(`if iszero(slt(${off}, sub(sub(calldatasize(), 4), 0x1f))) { revert(0, 0) }`);
    const cdPtr = this.fresh();
    out.push(`let ${cdPtr} := add(4, ${off})`); // the value's data (length word / tuple start)
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`);
    // a flat top-level value array CLEANS its elements on a RETURN echo (Bug A; solc's return
    // copy masks dirty bits), but the EVENT/ERROR decode VALIDATES every element (reverts on
    // dirty), so callers in that context pass forceValidate. Everything else always validates.
    const topClean = !forceValidate && t.kind === 'array' && t.length === undefined && isStaticValueType(t.element);
    // forceValidate marks the DECODE/re-encode context (abi.encode/encodeWith*/emit/error via
    // materializeArrayArg): an oversized inner length/offset is an ABI-decode failure -> revert(0,0),
    // matching solc. The return-echo path (forceValidate=false) keeps Panic 0x41.
    const size = this.abiEncFromCd(t, cdPtr, `add(${ptr}, 0x20)`, !topClean, out, forceValidate, enumRaw);
    out.push(`mstore(0x40, add(add(${ptr}, 0x20), ${size}))`);
    return { ptr, size: `add(0x20, ${size})` };
  }

  /** JETH242/243: resolve an aggregate ARGUMENT or internal-fn RETURN value (a dynamic value-element
   *  array, bytes/string, or a struct) to a MEMORY pointer for pass-/return-by-reference. A
   *  memory-local source ALIASES (the pointer is shared, so a callee mutation is visible to the
   *  caller, matching solc); a calldata source is COPIED to fresh memory (a value array MASKS dirty
   *  elements, like solc's calldata->memory copy); a storage source is copied via abiEncFromStorage
   *  (storage is canonical); a constructed literal / call result is already fresh memory. */
  private aggArgToMemPtr(a: Expr, ctx: LowerCtx, out: string[]): string {
    // abi.decode(data, T) / data.decode(T) yielding an array / struct: lowerAbiDecode already returns
    // a fresh decoded memory image pointer in the right layout ([len][elems] for an array, the
    // pointer-headed image for a dynamic struct, the flat ABI image for a static aggregate).
    if (a.kind === 'abiDecode') return this.lowerAbiDecode(a.data, [a.type], ctx, out)[0]!;
    // a whole DYNAMIC-ARRAY field of a calldata dyn-struct array element (xs[i].grid / xs[i].items) used
    // as a return-tuple component / fn arg: DEEP-COPY from its resolved calldata header into a fresh
    // pointer-headed memory image (cap = Panic 0x41, solc's calldata->memory deep-copy semantics).
    if (a.kind === 'cdFieldAggValue') {
      const hdr = this.cdFieldArrayHeader(a.place, ctx, out);
      return this.abiDecFromCdToImage(a.type, hdr, out, `${this.panic()}(0x41)`);
    }
    if (a.kind === 'cdNestedFieldAggValue') {
      const hdr = this.cdNestedFieldArrayHeader(a.place, a.indices, ctx, out);
      return this.abiDecFromCdToImage(a.type, hdr, out, `${this.panic()}(0x41)`);
    }
    // a whole VALUE-leaf sub-aggregate ELEMENT of a calldata array-of-array (let row: u256[] = xs[i],
    // for u256[][] / address[][] / Arr<u256,N>[]) bound to a memory local: resolve the element's calldata
    // base (bounds-checked, Panic 0x32 on OOB), then DEEP-COPY it into a fresh memory image via the
    // calldata->memory codec, MASKING value leaves (abiDecFromCdToImage's value-leaf rule). cap =
    // EMPTY revert: for a VALUE-element inner array (each element is 32 inline calldata bytes) any
    // oversized inner length fails the calldatasize bound BEFORE a memory-alloc overflow, so solc
    // empty-reverts (never Panic 0x41) - byte-identical to the `return xs[i]` echo (capEmptyRevert).
    // A reference-leaf element (bytes[][]/D[][]) never reaches here: the analyzer cleanly rejects that
    // bind (JETH200/JETH072), so the Panic-0x41 cd-to-mem cap is not needed on this path.
    if (a.kind === 'cdAggArrayElem') {
      const eb = this.cdArrayElemBase(a.arr, a.index, a.type, ctx, out);
      return this.abiDecFromCdToImage(a.type, eb, out);
    }
    // a DYNAMIC-array literal lowers to a fresh [len][elems] memory image (lowerExpr's arrayLit case);
    // a structNew / static fixed-array literal uses the static-aggregate image (allocAggToMem).
    if (a.kind === 'arrayLit') {
      if (a.type.kind === 'array' && a.type.length === undefined) return this.lowerExpr(a, ctx, out);
      // a FIXED-outer static-struct array literal (Arr<P,N>) is POINTER-HEADED (N pointer words, each ->
      // a fresh element image), NOT the flat static image - build it via the nested-array literal builder
      // (the same image the local-decl / return paths use). allocAggToMem would emit a flat blob whose
      // leading words are then misread as element pointers (zeros), a silent miscompile.
      // P1-7: a FIXED-outer DYNAMIC-element array literal (Arr<string,N>, Arr<bytes,N>, Arr<u256[],N>) is
      // ALSO pointer-headed (N absolute-pointer words, each -> a [len][data] / [len][elems] blob), built by
      // the SAME nested-array literal builder (mirrors nestedMemImagePtr's arrayLit branch). allocAggToMem
      // would flatten it wrong. Reached only when such a literal is passed as an internal-fn / error arg.
      if (isStaticStructFixedLeafArray(a.type) || isDynamicType(a.type)) return this.buildNestedMemArrayLit(a, ctx, out);
      return this.allocAggToMem(a, ctx, out);
    }
    // a DYNAMIC-field struct (constructor / memory / storage / calldata source) uses the
    // pointer-headed image builder; only a STATIC structNew uses the flat ABI image.
    if (a.type.kind === 'struct' && isDynamicType(a.type)) return this.buildDynStructLocal(a.type, a, ctx, out);
    if (a.kind === 'structNew') return this.allocAggToMem(a, ctx, out);
    // #2 storage-to-mem-copy: a whole MAPPING-VALUE array (let row = this.m[k], m: mapping<K, u256[]> /
    // bytes[] / u256[][] / Arr<P,N> / ...). resolveMapAccess types this.m[k] as a mapStorageValue (NOT
    // an arrayValue with a mapArray base), so route it here: resolve the value-array's root slot
    // (mappingSlot), then deep-copy from that slot exactly like a stateArray source (a reference-element
    // array -> the pointer-headed image twin; a value-element array -> the byte-invariant
    // abiEncFromStorage copy that must not regress).
    if (a.kind === 'mapStorageValue' && a.type.kind === 'array') {
      const rootSlot = this.mappingSlot(a.baseSlot, a.keys, ctx, out);
      if (!isStaticValueType(a.type.element)) {
        return this.abiDecFromStorageToImage(a.type, rootSlot, ctx, out);
      }
      const dst = this.fresh();
      out.push(`let ${dst} := mload(0x40)`);
      const size = this.abiEncFromStorage(a.type, rootSlot, 0, dst, out);
      out.push(`mstore(0x40, add(${dst}, ${size}))`);
      return dst;
    }
    if (a.kind === 'arrayValue') {
      const b = a.arr.base;
      if (b.kind === 'memArray') return this.ctxLookup(ctx, b.varName); // memory local: ALIAS
      if (b.kind === 'memArrayExpr') return this.lowerExpr(b.expr, ctx, out);
      // P1-8: a CALLDATA ARRAY SLICE bound to a memory local (`let b: u256[] = a.slice(...)`) or used as
      // a whole value (return / arg): resolve the narrowed (offset, length) then DEEP-COPY into a fresh
      // [len][elems] value-array image (masking dirty leaves, byte-identical to solc's calldata->memory
      // slice copy). Only value-word / static-struct element slices reach here (analyzer gate).
      if (b.kind === 'cdSlice') {
        const ref = this.lowerArrayRef(a.arr, ctx, out);
        if (ref.src !== 'calldata') throw new UnsupportedError('a calldata array slice must resolve to calldata');
        return this.cdSliceToMem(a.arr.elem, ref.offset, ref.length, out);
      }
      // a WHOLE dynamic-array FIELD of a calldata dyn-struct (param `s.tags` or array element
      // `xs[i].tags`) bound to a memory local: DEEP-COPY from the field's resolved calldata header
      // into a fresh memory image. Reuses the SAME cdFieldArrayHeader + abiDecFromCdToImage codec the
      // cdFieldAggValue (array/struct field) path uses; here the leaf is bytes/string (B2) or a value
      // element (u256[]). cap = Panic 0x41 (an oversized inner len / alloc overflow), matching solc's
      // calldata->memory deep-copy; truncated/OOB source EMPTY-reverts via the codec's bounds checks.
      if (b.kind === 'cdDynArrayField') {
        const hdr = this.cdFieldArrayHeader(b.place, ctx, out);
        return this.abiDecFromCdToImage(a.type, hdr, out, `${this.panic()}(0x41)`);
      }
      // W5C: a whole FIXED-outer dynamic-element FIELD of a calldata dyn-struct (let ys: Arr<string,N>
      // = s.xs / an internal-call arg): the field tail IS the N-word offset table (no [len] word);
      // require it readable, then DEEP-COPY into a fresh N-pointer memory image via the fixed-outer
      // branch of abiDecFromCdToImage (Panic 0x41 alloc cap, solc's calldata->memory deep copy).
      if (b.kind === 'cdDynFixedDynField') {
        const hdr = this.cdFieldArrayHeader(b.place, ctx, out);
        out.push(`if gt(add(${hdr}, ${b.length * 32}), calldatasize()) { revert(0, 0) }`);
        return this.abiDecFromCdToImage(a.type, hdr, out, `${this.panic()}(0x41)`);
      }
      if (b.kind === 'calldataArray') {
        // cd-to-mem-copy: a whole REFERENCE-element calldata array (bytes[]/string[]/u256[][]/P[]...) deep-
        // copies into a fresh POINTER-HEADED memory image via abiDecFromCdToImage (the calldata twin of
        // abiDecFromMemToImage). The param's [len] word sits one word before its element/offset-table base
        // (cdArrays stores `offset` = tableStart = the word AFTER [len], so the [len] word is offset - 0x20).
        // Reuses solc's calldata-decode revert semantics (EMPTY-revert on OOB / truncated / oversized). A
        // VALUE-element array (u256[]) is NOT routed here: it keeps the echoParam [len][elems] copy below
        // (byte-invariant, must not regress).
        if (a.type.kind === 'array' && !isStaticValueType(a.type.element)) {
          const cd = ctx.cdArrays.get(b.name);
          if (!cd) throw new UnsupportedError(`calldata array '${b.name}' is not registered`);
          // solc's calldata->memory deep copy hits the MEMORY allocation guard (Panic 0x41) on an
          // oversized inner length / alloc overflow, NOT the calldata-decode empty revert; pass it.
          // W5B: a FIXED-outer array of a DYNAMIC element (Arr<string,N>/Arr<bytes,N>/Arr<u256[],N>)
          // has NO [len] word - cdArrays.offset IS the N-word per-element offset-table base (= the
          // tuple start the relative offsets resolve against), exactly what abiDecFromCdToImage's
          // fixed-of-dynamic branch consumes. Subtracting 0x20 here (the dynamic-outer [len] header
          // rebase) read the table one word early - a MISCOMPILE for `let ys: Arr<string,N> = p` and
          // for forwarding p as an internal-call arg (wrong element bytes / spurious revert).
          if (a.type.length !== undefined) {
            return this.abiDecFromCdToImage(a.type, cd.offset, out, `${this.panic()}(0x41)`);
          }
          return this.abiDecFromCdToImage(a.type, `sub(${cd.offset}, 0x20)`, out, `${this.panic()}(0x41)`);
        }
        // COPY: masking dirty non-enum elements, RAW for enum words (W6C: solc's convert-to-memory
        // does NOT validate enums during the copy; the element read Panics 0x21 lazily).
        const { ptr } = this.echoParam(b.name, a.type, ctx, out, false, true);
        const mp = this.fresh();
        out.push(`let ${mp} := add(${ptr}, 0x20)`); // skip the [0x20] offset wrapper -> [len][elems]
        return mp;
      }
      // storage source (this.arr / this.m[k] / a nested inner array / a FIXED-outer array this.fa):
      // DEEP-COPY a fresh memory image. For a dynamic outer the slot holds [len]; for a FIXED outer
      // (fixedArray base, #4) it is the base slot of element 0 (no length header), which is exactly
      // what abiDecFromStorageToImage's fixed-array branch consumes.
      let lenSlot: string;
      if (b.kind === 'stateArray') lenSlot = String(b.slot);
      else if (b.kind === 'mapArray') lenSlot = this.mappingSlot(b.baseSlot, b.keys, ctx, out);
      else if (b.kind === 'placeArray') lenSlot = this.lowerPlace(b.path, ctx, out).slot;
      else if (b.kind === 'fixedArray') lenSlot = String(b.baseSlot);
      else throw new UnsupportedError(`aggregate argument from array source '${b.kind}' is not supported`);
      // A REFERENCE-element array (bytes[]/string[]/u256[][]/P[]) needs a POINTER-HEADED memory image
      // (absolute pointers), which abiEncFromStorage does NOT produce (it emits RELATIVE ABI offsets -
      // a silent miscompile if bound as a memArray local). Route it through the storage->image twin.
      // A VALUE-element array (u256[]) is byte-invariant ([len][inline]); keep the abiEncFromStorage
      // copy to avoid churning the proven value-element path.
      if (a.type.kind === 'array' && !isStaticValueType(a.type.element)) {
        return this.abiDecFromStorageToImage(a.type, lenSlot, ctx, out);
      }
      const dst = this.fresh();
      out.push(`let ${dst} := mload(0x40)`);
      const size = this.abiEncFromStorage(a.type, lenSlot, 0, dst, out);
      out.push(`mstore(0x40, add(${dst}, ${size}))`);
      return dst;
    }
    if (isBytesLike(a.type)) {
      const { mp } = this.toMemory(this.lowerDynamic(a, ctx, out), out); // alias (memory) or copy (cd/storage)
      return mp;
    }
    // a calldata struct / fixed-array param forwarded as an INTERNAL-CALL arg: COPY its ABI-unpacked
    // image to memory. The callee binds the param as a MEMORY reference and reads it with the memory-
    // local layout, so the copy MUST match that layout exactly.
    if (a.kind === 'cdAggregateValue') {
      // A whole calldata static-STRUCT-fixed-array (Arr<In,N>, Arr<Arr<In,N>,M>, Arr<In,N>[]...) is
      // STATIC but POINTER-HEADED in memory: the callee's memAggregate/Batch-A resolver reads a[i] as
      // the i-th ABSOLUTE-pointer word (memStaticElem=false). allocAggFromCalldata produces the FLAT
      // ABI image (N inline es-word blocks) - correct for the `return a` / `abi.encode(a)` echo paths
      // (which re-encode flat) but a MISCOMPILE here (the callee reads the flat leading words as element
      // pointers -> all-zero). Route it through the SAME pointer-headed calldata->memory codec the memory-
      // local bind / dyn-struct-array-element paths use (abiDecFromCdToImage's fixed-outer static-struct
      // branch: N absolute-pointer words, each -> a fresh validated per-element image), byte-identical to
      // the memory-local image the callee expects. A whole static STRUCT (flat) and a value fixed array
      // Arr<u256,N> (flat inline, memStaticElem undefined) keep the correct allocAggFromCalldata flat copy.
      if (a.type.kind === 'array' && isStaticStructFixedLeafArray(a.type)) {
        const ph = ctx.cdParamHead.get(a.param);
        if (!ph) throw new UnsupportedError(`unbound struct-copy param ${a.param}`);
        return this.abiDecFromCdToImage(a.type, String(ph.head), out);
      }
      return this.allocAggFromCalldata(a.param, a.type, ctx, out, true);
    }
    // a DYNAMIC-field struct arg: pointer-headed image (memory source ALIASES; storage/calldata/
    // constructor source is COPIED to fresh memory) - the same builder a dynamic-struct local uses.
    if (a.type.kind === 'struct' && isDynamicType(a.type)) return this.buildDynStructLocal(a.type, a, ctx, out);
    // a STATIC struct from a STORAGE source (this.st / this.m[k] / this.arr[i] / a nested place)
    // forwarded as an internal-fn / @library struct arg: solc copies it storage->memory (the param is
    // `S memory`), so build a fresh flat inline memory image via abiEncFromStorage - the same image a
    // memory static-struct local holds. Without this the structValue fell through to lowerExpr and threw
    // (a reference value in a non-reference context). A MEMORY struct arg keeps its alias (lowerExpr).
    if (
      a.type.kind === 'struct' &&
      isStaticType(a.type) &&
      (a.kind === 'structValue' ||
        a.kind === 'mapStorageValue' ||
        a.kind === 'structArrayElem' ||
        a.kind === 'placeRead')
    ) {
      const slot = this.structSrcSlot(a, ctx, out);
      const dst = this.fresh();
      out.push(`let ${dst} := mload(0x40)`);
      const size = this.abiEncFromStorage(a.type, slot, 0, dst, out);
      out.push(`mstore(0x40, add(${dst}, ${size}))`);
      return dst;
    }
    // a struct value (memAggregate alias / storage) or a call result (already a pointer).
    return this.lowerExpr(a, ctx, out);
  }

  /** P1-8: DEEP-COPY a CALLDATA ARRAY SLICE (a resolved runtime `offset`/`length` element region, element
   *  type `elem`) into a fresh memory [len][elems] image; returns its absolute pointer. Mirrors solc's
   *  calldata->memory copy of `T[] memory c = a[s:e]`: value/static-struct elements are copied inline with
   *  dirty leaves MASKED (never reverted). The slice `length` already bounds the source region against
   *  calldatasize (the offset region belongs to the enclosing param, validated at decode), so the copy has
   *  no additional source-bounds revert. Only value-word / static-struct elements reach here (analyzer
   *  gate: a dynamic-element slice is left rejected). */
  private cdSliceToMem(elem: JethType, offset: string, length: string, out: string[]): string {
    // W5B: a STATIC-STRUCT element slice (let s: P[] = ps.slice(a, b) / an internal-call arg): the
    // in-memory P[] image is POINTER-HEADED ([len] + a len-word absolute-pointer table, each -> a fresh
    // flat element image), NOT the flat [len][elems] value layout. Claim the table first (element images
    // alloc PAST it), then per element decode the contiguous calldata block at offset + i*stride through
    // abiDecFromCdToImage's static branch (per-leaf VALIDATION - dirty narrow fields revert empty,
    // exactly like solc's `P[] memory s = ps[a:b]` copy). The slice window is already bounded inside the
    // validated base region, so no extra source-bounds check is needed; the alloc-overflow cap (Panic
    // 0x41) mirrors the whole-P[]-param copy.
    if (elem.kind === 'struct') {
      const es = abiHeadWords(elem) * 32;
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      const tableEnd = this.fresh();
      out.push(`let ${tableEnd} := add(add(${ptr}, 0x20), mul(${length}, 0x20))`);
      out.push(`if or(gt(${tableEnd}, 0xffffffffffffffff), lt(${tableEnd}, ${ptr})) { ${this.panic()}(0x41) }`);
      out.push(`mstore(${ptr}, ${length})`);
      out.push(`mstore(0x40, ${tableEnd})`); // claim the table; per-element images alloc PAST it
      const dstHead = this.fresh();
      out.push(`let ${dstHead} := add(${ptr}, 0x20)`);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${length}) { ${i} := add(${i}, 1) } {`);
      const inner: string[] = [];
      const esrc = this.fresh();
      inner.push(`let ${esrc} := add(${offset}, mul(${i}, ${es}))`);
      const ip = this.fresh();
      inner.push(`let ${ip} := ${this.abiDecFromCdToImage(elem, esrc, inner, `${this.panic()}(0x41)`)}`);
      inner.push(`mstore(add(${dstHead}, mul(${i}, 0x20)), ${ip})`);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
      return ptr;
    }
    // Only a VALUE-WORD element reaches here (analyzer gate); stride is one 32-byte ABI word.
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    // total = 0x20 (len word) + length*32, with an unsigned-overflow cap (Panic 0x41) matching solc's
    // memory allocation guard on an oversized copy.
    const nc = this.fresh();
    out.push(`let ${nc} := add(add(${ptr}, 0x20), mul(${length}, 0x20))`);
    out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${ptr})) { ${this.panic()}(0x41) }`);
    out.push(`mstore(${ptr}, ${length})`);
    out.push(`mstore(0x40, ${nc})`);
    const dstHead = this.fresh();
    out.push(`let ${dstHead} := add(${ptr}, 0x20)`);
    const i = this.fresh();
    out.push(`for { let ${i} := 0 } lt(${i}, ${length}) { ${i} := add(${i}, 1) } {`);
    const inner: string[] = [];
    const w = this.fresh();
    inner.push(`let ${w} := calldataload(add(${offset}, mul(${i}, 0x20)))`);
    // masked/cleaned like solc's calldata->memory copy. W6C: an ENUM element copies RAW (solc's
    // slice-to-memory copy does NOT validate enums; reading the element from memory Panics 0x21
    // lazily - verified vs 0.8.35: a clean-element read beside a dirty one succeeds).
    if ((elem as { enumMembers?: string[] }).enumMembers) {
      inner.push(`mstore(add(${dstHead}, mul(${i}, 0x20)), ${w})`);
    } else {
      inner.push(`mstore(add(${dstHead}, mul(${i}, 0x20)), ${this.cleanCalldataElem(elem, w)})`);
    }
    out.push(...inner, `}`);
    return ptr;
  }

  /** Materialize a DYNAMIC-array argument (G3, for @error/@event head/tail) into a memory blob
   *  holding its ABI tail encoding `[len][elements...]`, returning a frozen pointer + byte size.
   *  Calldata-param arrays reuse echoParam (unbounded element nesting); value-element memory
   *  arrays are already in ABI tail layout. Other sources are gated. */
  private materializeArrayArg(arg: Expr, ctx: LowerCtx, out: string[]): { mp: string; size: string } {
    // a MEMORY-sourced NESTED value array bearing a DYNAMIC level (u256[][], Arr<u256[],N>, ...): resolve
    // its memory image, then ABI-encode it (relative offsets) into a fresh tail blob via abiEncFromMem.
    // The blob IS the ABI tail (mp points at [len]/the offset table, size is its byte length) - the
    // contract buildAbiEncodeStd / the event/error tail expects. A CALLDATA-sourced nested array keeps
    // the existing echoParam recursive encoder (the calldataArray branch below); a storage source keeps
    // abiEncFromStorage. Only an in-memory image (literal / new Array / memArray / memAggregate / a
    // nested inner element) is laid out by abiEncFromMem.
    const memSourced =
      arg.kind === 'arrayLit' ||
      arg.kind === 'newArray' ||
      (arg.kind === 'arrayValue' &&
        (arg.arr.base.kind === 'memArray' || arg.arr.base.kind === 'memArrayExpr'));
    // Residual B: a P[] (static struct) / bytes[] / string[] memory arg also lays out via abiEncFromMem
    // (each element is an inline struct block, or a [len][data] tail behind the offset table).
    const codecSourced =
      (isNestedValueArray(arg.type) && isDynamicType(arg.type)) ||
      isAggregateLeafArray(arg.type) ||
      (isStaticStructAnyLeafArray(arg.type) && isDynamicType(arg.type)); // Batch A: Arr<P,N>[] dynamic outer
    // a whole DYNAMIC-ARRAY field of a calldata dyn-struct array element (xs[i].grid / xs[i].items) /
    // a descended inner array (xs[i].grid[j]) as an abi.encode/encodePacked arg: re-encode it DIRECTLY
    // from its resolved calldata header into a fresh ABI TAIL blob (mp points at [len]/the offset table,
    // size is the tail byte length). This is solc's abi.encode behavior: a direct calldata->ABI re-encode
    // with NO memory materialization, so a malformed inner length/offset is an ABI-decode failure ->
    // EMPTY revert (capEmptyRevert=true), empirically verified vs solc 0.8.35 (oversized inner len -> 0x).
    if (arg.kind === 'cdFieldAggValue' || arg.kind === 'cdNestedFieldAggValue') {
      const hdr =
        arg.kind === 'cdFieldAggValue'
          ? this.cdFieldArrayHeader(arg.place, ctx, out)
          : this.cdNestedFieldArrayHeader(arg.place, arg.indices, ctx, out);
      const validate = !isValueLeafArray(arg.type);
      const dst = this.fresh();
      out.push(`let ${dst} := mload(0x40)`);
      const sz = this.fresh();
      out.push(`let ${sz} := ${this.abiEncFromCd(arg.type, hdr, dst, validate, out, true)}`);
      out.push(`mstore(0x40, add(${dst}, ${sz}))`);
      return { mp: dst, size: sz };
    }
    if (codecSourced && memSourced) {
      const mp = this.nestedMemImagePtr(arg, ctx, out);
      const dst = this.fresh();
      out.push(`let ${dst} := mload(0x40)`);
      const sz = this.fresh();
      out.push(`let ${sz} := ${this.abiEncFromMem(arg.type, mp, dst, ctx, out)}`);
      out.push(`mstore(0x40, add(${dst}, ${sz}))`);
      return { mp: dst, size: sz };
    }
    // P0-33: a MEMORY-sourced FIXED-outer dynamic-element array (Arr<string,N>, Arr<bytes,N>,
    // Arr<u256[],N>) used as an abi.encode/encodePacked arg. Its type is dynamic (a dynamic leaf) but
    // t.length !== undefined, so it is placed in the tail with a head OFFSET (the {mp,size} caller
    // branch), NOT inline. Its memory image is N pointer words (a memAggregate local / an inline
    // arrayLit); nestedMemImagePtr resolves it and abiEncFromMem's fixed-outer-dynamic branch produces
    // the self-contained ABI tail (N-word offset table relative to mp, then per-element dynamic tails,
    // NO leading length word). Mirrors the emit(E(m)) event-data path (materializeFixedDynLeafTail).
    if (this.isMemFixedDynLeafArg(arg)) {
      return this.materializeFixedDynLeafTail(arg, ctx, out);
    }
    if (
      (arg.kind === 'newArray' || arg.kind === 'call') &&
      arg.type.kind === 'array' &&
      arg.type.length === undefined &&
      isStaticValueType(arg.type.element)
    ) {
      // a value-element dynamic array produced directly by `new Array<T>(n)` or an internal call
      // (this.mk()) used as an abi.encode/encodePacked arg: lower it to its [len][elems] memory
      // pointer (value elements, ABI tail layout already), exactly like a memArray local.
      const mp = this.lowerExpr(arg, ctx, out);
      return { mp, size: `mul(add(mload(${mp}), 1), 0x20)` };
    }
    if (arg.kind !== 'arrayValue')
      throw new UnsupportedError(`array argument must be an array value, got '${arg.kind}'`);
    const base = arg.arr.base;
    if (base.kind === 'cdDynArrayField') {
      // a calldata dyn-struct's leaf dynamic-array field (abi.encode(p.tags)): re-encode it DIRECTLY
      // from its resolved calldata header into a fresh ABI TAIL blob (the same cdFieldArrayHeader +
      // abiEncFromCd codec the cdFieldAggValue path and a return component use). A malformed inner
      // length/offset is an ABI-decode failure -> EMPTY revert (capEmptyRevert), byte-identical to
      // solc's abi.encode. (Previously fell to the storage-source else and threw JETH900.)
      const hdr = this.cdFieldArrayHeader(base.place, ctx, out);
      const validate = !isValueLeafArray(arg.type);
      const dst = this.fresh();
      out.push(`let ${dst} := mload(0x40)`);
      const sz = this.fresh();
      out.push(`let ${sz} := ${this.abiEncFromCd(arg.type, hdr, dst, validate, out, true)}`);
      out.push(`mstore(0x40, add(${dst}, ${sz}))`);
      return { mp: dst, size: sz };
    }
    if (base.kind === 'cdDynFixedDynField') {
      // W5C: a calldata dyn-struct's FIXED-outer dynamic-element field (abi.encode(p.xs) / an event
      // arg, xs: Arr<string,N>): re-encode DIRECTLY from its calldata tail (the N-word offset table at
      // the field offset - cdFieldArrayHeader resolves it) into a fresh self-contained ABI tail blob.
      // The table itself must lie within calldata (empty revert, like the sibling tail decodes).
      const hdr = this.cdFieldArrayHeader(base.place, ctx, out);
      out.push(`if gt(add(${hdr}, ${base.length * 32}), calldatasize()) { revert(0, 0) }`);
      const validate = !isValueLeafArray(arg.type);
      const dst = this.fresh();
      out.push(`let ${dst} := mload(0x40)`);
      const sz = this.fresh();
      out.push(`let ${sz} := ${this.abiEncFromCd(arg.type, hdr, dst, validate, out, true)}`);
      out.push(`mstore(0x40, add(${dst}, ${sz}))`);
      return { mp: dst, size: sz };
    }
    if (base.kind === 'cdSlice') {
      // W5B shape 3: abi.encode(a.slice(...)) / keccak256(abi.encode(...)) / a mixed abi.encode arg:
      // re-encode the narrowed (offset, length) element region DIRECTLY from calldata into a fresh ABI
      // tail blob [len][elements...]. solc VALIDATES each element INSIDE the slice window (empty revert
      // on a dirty uintN/int N/bool/address/bytesN and an out-of-range enum), exactly like a whole
      // calldata-array arg - and does NOT validate elements outside the window (verified empirically vs
      // solc 0.8.35: dirty-in-slice reverts empty, dirty-outside-slice encodes fine). A STATIC-STRUCT
      // element re-encodes per-leaf through the same validated abiEncFromCd copy at the element stride.
      const ref = this.lowerArrayRef(arg.arr, ctx, out);
      if (ref.src !== 'calldata') throw new UnsupportedError('a calldata array slice must resolve to calldata');
      const stride = abiHeadWords(arg.arr.elem) * 32;
      const dst = this.fresh();
      out.push(`let ${dst} := mload(0x40)`);
      const sz = this.fresh();
      out.push(`let ${sz} := add(0x20, mul(${ref.length}, ${stride}))`);
      out.push(`mstore(${dst}, ${ref.length})`);
      out.push(`mstore(0x40, add(${dst}, ${sz}))`);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${ref.length}) { ${i} := add(${i}, 1) } {`);
      const inner: string[] = [];
      const esrc = this.fresh();
      inner.push(`let ${esrc} := add(${ref.offset}, mul(${i}, ${stride}))`);
      const edst = this.fresh();
      inner.push(`let ${edst} := add(add(${dst}, 0x20), mul(${i}, ${stride}))`);
      this.abiEncFromCd(arg.arr.elem, esrc, edst, true, inner, true);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
      return { mp: dst, size: sz };
    }
    let mpExpr: string;
    let sizeExpr: string;
    if (base.kind === 'calldataArray') {
      // an @event/@error array arg: solc VALIDATES every value element (reverts on dirty bits),
      // unlike a RETURN echo which cleans, so force validation here.
      const { ptr, size } = this.echoParam(base.name, arg.type, ctx, out, true);
      mpExpr = `add(${ptr}, 0x20)`; // skip the single-value [0x20] offset wrapper
      sizeExpr = `sub(${size}, 0x20)`;
    } else if (base.kind === 'memArray') {
      mpExpr = this.ctxLookup(ctx, base.varName);
      sizeExpr = `mul(add(mload(${mpExpr}), 1), 0x20)`; // [len][e0..] value elements
    } else if (base.kind === 'memArrayExpr') {
      mpExpr = this.lowerExpr(base.expr, ctx, out);
      sizeExpr = `mul(add(mload(${mpExpr}), 1), 0x20)`;
    } else {
      // a STORAGE source (this.arr / this.m[k] / a nested inner array this.dd[i] / this.s.xs):
      // build a fresh [len][elements...] ABI tail image via abiEncFromStorage (the canonical
      // transcode aggArgToMemPtr already uses). The result IS the ABI tail blob, so mp points at
      // the [len] word and size is its full byte length (length word + element / offset-table /
      // tail bytes), matching the value-element memArray contract and the calldata echo.
      let lenSlot: string;
      if (base.kind === 'stateArray') lenSlot = String(base.slot);
      else if (base.kind === 'mapArray') lenSlot = this.mappingSlot(base.baseSlot, base.keys, ctx, out);
      else if (base.kind === 'placeArray') lenSlot = this.lowerPlace(base.path, ctx, out).slot;
      // a FIXED-outer storage array whose element is DYNAMIC (Arr<D,N>, D has a dynamic field): the
      // base slot is element 0 (no length header). abiEncFromStorage's fixed-array-of-dynamic branch
      // emits the N-word offset table + per-element tails (no length word), the canonical ABI tail of
      // a fixed dynamic-element array - byte-identical to solc's abi.encode/return of this aggregate.
      else if (base.kind === 'fixedArray') lenSlot = String(base.baseSlot);
      else
        throw new UnsupportedError(
          `a dynamic-array @error/@event argument from a '${base.kind}' source is not supported yet`,
        );
      const sdst = this.fresh();
      out.push(`let ${sdst} := mload(0x40)`);
      const ssz = this.abiEncFromStorage(arg.type, lenSlot, 0, sdst, out);
      const sm = this.fresh();
      out.push(`let ${sm} := ${ssz}`);
      out.push(`mstore(0x40, add(${sdst}, ${sm}))`);
      return { mp: sdst, size: sm };
    }
    const mp = this.fresh();
    out.push(`let ${mp} := ${mpExpr}`);
    // W6C: a MEMORY-sourced ENUM array (a bound local, possibly holding RAW dirty words from the
    // calldata bind copy) is range-checked here - solc's abi.encode/emit/revert/packed encoders
    // Panic(0x21) on an out-of-range enum read from memory. No-op for valid images / non-enums.
    if (base.kind === 'memArray' || base.kind === 'memArrayExpr') {
      this.validateEnumMemArray(arg.type, mp, out);
    }
    const size = this.fresh();
    out.push(`let ${size} := ${sizeExpr}`);
    return { mp, size };
  }

  /** A MEMORY-sourced FIXED-outer dynamic-element array value (Arr<bytes,N>/Arr<string,N>/Arr<u256[],N>)
   *  that materializeArrayArg throws JETH900 on: a fixed `Arr<T,N>` local is a `memAggregate`, or an
   *  inline literal is an `arrayLit`. (A fixed-outer type never has a memArray/memArrayExpr base - those
   *  are DYNAMIC-array locals - and never a newArray/call - those yield dynamic arrays.) A CALLDATA /
   *  STORAGE source is NOT matched here: those ride materializeArrayArg's existing echoParam /
   *  abiEncFromStorage tail, which is already byte-identical. Routes the @event topic/data arg to
   *  materializeFixedDynLeafTail (nestedMemImagePtr + abiEncFromMem). */
  private isMemFixedDynLeafArg(a: Expr): boolean {
    if (a.type.kind !== 'array' || a.type.length === undefined || !isDynamicType(a.type)) return false;
    return a.kind === 'memAggregate' || a.kind === 'arrayLit';
  }

  /** Build the ABI tail (an N-word offset table relative to `mp`, then per-element tails; NO length
   *  word) for a FIXED-outer dynamic-element event array (Arr<bytes,N>, Arr<string,N>, Arr<u256[],N>,
   *  ...). materializeArrayArg intentionally rejects these fixed-outer aggregates as an abi.encode /
   *  pass-as-arg (Edge D), and it also threw JETH900 for them here (an @event data / indexed-topic arg
   *  from a memAggregate/literal source), a CRASH on input solc accepts. Instead resolve the
   *  pointer-headed memory image (nestedMemImagePtr: a memAggregate local, a literal, a memArray) and
   *  re-encode it into a fresh tail via abiEncFromMem's fixed-outer-dynamic branch. `{mp, size}` is the
   *  self-contained ABI tail of the fixed dynamic-element aggregate: as non-indexed @event DATA it is
   *  copied verbatim behind a head offset (byte-identical to solc's log data); as an indexed TOPIC it is
   *  the exact `tail` encodeArrayTopicBlob's fixed-outer branch walks (base = mp, offsets relative to
   *  base), so keccak256 of the packed-padded preimage == solc's topic. Verified vs solc for bytes[2]/
   *  [3], string[2] with a >31-byte leaf, and uint256[][2]. */
  private materializeFixedDynLeafTail(arg: Expr, ctx: LowerCtx, out: string[]): { mp: string; size: string } {
    const img = this.nestedMemImagePtr(arg, ctx, out);
    const dst = this.fresh();
    out.push(`let ${dst} := mload(0x40)`);
    const sz = this.fresh();
    out.push(`let ${sz} := ${this.abiEncFromMem(arg.type, img, dst, ctx, out)}`);
    out.push(`mstore(0x40, add(${dst}, ${sz}))`);
    return { mp: dst, size: sz };
  }

  /** Materialize a whole STATIC fixed-array / struct value to a fresh memory blob of ABI-encoded
   *  padded leaf words (one word per leaf), for an indexed-event keccak topic. Sources: a @state
   *  fixed array / struct (storage -> abiEncFromStorage) or a whole static calldata aggregate param
   *  (echoStaticParam). Returns {mp, size}; keccak256(mp, size) == solc's keccak256(abi.encode(v)). */
  /** A static-struct fixed array (Arr<P,N> / Arr<Arr<P,M>,N>) whose MEMORY image is POINTER-HEADED
   *  (N absolute-pointer words, post the Cat-B / Batch-A redesign) AND whose source is a standalone
   *  memory image (NOT an ABI-flattened-inline struct FIELD). Such a value must be transcoded to the
   *  flat inline ABI body via abiEncFromMem before keccak/mcopy (an event topic preimage / event data
   *  head / abi.encode). Mirrors the memFixedSrc test in buildAbiEncodeStd, which EXCLUDES aggFieldRead
   *  (a nested static-agg field is already flattened inline in its parent image - transcoding it would
   *  misread the inline words as pointers). A static VALUE aggregate (Arr<u256,N>, a value struct) is
   *  already flat and is NOT matched here. */
  private isPointerHeadedStaticAggArg(a: Expr): boolean {
    if (!isStaticStructFixedLeafArray(a.type)) return false;
    return (
      a.kind === 'arrayLit' ||
      a.kind === 'newArray' ||
      a.kind === 'memAggregate' ||
      a.kind === 'arrayGet' ||
      a.kind === 'call' ||
      (a.kind === 'arrayValue' && (a.arr.base.kind === 'memArray' || a.arr.base.kind === 'memArrayExpr'))
    );
  }

  /** Transcode a pointer-headed memory static-struct fixed array (Arr<P,N>) to a fresh FLAT inline ABI
   *  image (abiHeadWords words) via abiEncFromMem - the identical flattening abi.encode uses. Returns the
   *  blob pointer. Only valid when isPointerHeadedStaticAggArg(a) is true. */
  private flattenPointerHeadedStaticAgg(a: Expr, ctx: LowerCtx, out: string[]): string {
    const mp = this.aggArgToMemPtr(a, ctx, out);
    const blob = this.fresh();
    out.push(`let ${blob} := mload(0x40)`);
    const sz = this.fresh();
    out.push(`let ${sz} := ${this.abiEncFromMem(a.type, mp, blob, ctx, out)}`);
    out.push(`mstore(0x40, add(${blob}, ${sz}))`);
    return blob;
  }

  private materializeStaticAggToMem(arg: Expr, ctx: LowerCtx, out: string[]): { mp: string; size: string } {
    if (arg.kind === 'cdAggregateValue') {
      // An indexed event arg emitted DIRECTLY from a calldata param: solc VALIDATES the value-leaf
      // words (reverts on dirty high/low bits), unlike a return echo which masks. Force validation
      // so a dirty calldata fixed-array reverts byte-identically to solc (not a masked success).
      const { ptr, size } = this.echoStaticParam(arg.param, arg.type, ctx, out, true);
      return { mp: ptr, size };
    }
    let slot: string;
    if (arg.kind === 'structValue') slot = String(arg.baseSlot);
    else if (arg.kind === 'arrayValue' && arg.arr.base.kind === 'fixedArray') slot = String(arg.arr.base.baseSlot);
    else {
      // a POINTER-HEADED memory Arr<P,N> (static-struct fixed array): its image is N pointer words, so
      // transcode to the flat inline ABI body first (keccak over the pointer header would be wrong bytes -
      // the indexed-topic / event-data MISCOMPILE the redesign introduced). Every other memory source
      // (value arrays/structs, a flattened-inline static-agg field) keeps its already-flat aggToMemPtr image.
      if (this.isPointerHeadedStaticAggArg(arg)) {
        return { mp: this.flattenPointerHeadedStaticAgg(arg, ctx, out), size: String(abiHeadWords(arg.type) * 32) };
      }
      // a constructed / memory / mapping-value / struct-array-element source: aggToMemPtr builds the
      // ABI-unpacked image (one word per leaf), so keccak256(mp, abiHeadWords*32) == keccak256(abi.encode(v)).
      // W6C: a fixed ENUM array image is range-checked before it is hashed into the topic
      // (Panic 0x21) - a bound memory local may hold RAW dirty words from the bind copy.
      const aggMp = this.aggToMemPtr(arg, ctx, out);
      this.validateEnumMemArray(arg.type, aggMp, out);
      return { mp: aggMp, size: String(abiHeadWords(arg.type) * 32) };
    }
    const dst = this.fresh();
    out.push(`let ${dst} := mload(0x40)`);
    const size = this.abiEncFromStorage(arg.type, slot, 0, dst, out);
    const sz = this.fresh();
    out.push(`let ${sz} := ${size}`);
    out.push(`mstore(0x40, add(${dst}, ${sz}))`);
    return { mp: dst, size: sz };
  }

  /** Echo a whole STATIC struct / fixed-array calldata param (G5). The data is INLINE at the
   *  param head (no offset word) and the return is flat (no 0x20 wrapper, since static types
   *  are returned inline). Matching solc's decode-to-memory: a pure VALUE-leaf fixed array
   *  CLEANS (masks) its leaves, while a struct (or struct-element array) VALIDATES its fields
   *  (the struct branch of abiEncFromCd forces field validation regardless of this flag). */
  private echoStaticParam(
    name: string,
    t: JethType,
    ctx: LowerCtx,
    out: string[],
    forceValidate = false,
  ): { ptr: string; size: string } {
    const ph = ctx.cdParamHead.get(name);
    if (!ph) throw new UnsupportedError(`unbound echo param ${name}`);
    const leaf = (ty: JethType): JethType => (ty.kind === 'array' && ty.length !== undefined ? leaf(ty.element) : ty);
    const validate = forceValidate || !(t.kind === 'array' && isStaticValueType(leaf(t)));
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    const size = this.abiEncFromCd(t, String(ph.head), ptr, validate, out);
    out.push(`mstore(0x40, add(${ptr}, ${size}))`);
    return { ptr, size };
  }

  /** Recursively re-encode a calldata value of type `t` (DATA at calldata byte
   *  `cdPtr`) into a fresh ABI blob at memory `dst`. Returns a Yul expr for the byte
   *  size written. Compile-time recursion over `t` => UNBOUNDED nesting depth; array
   *  lengths drive runtime loops. Inner offsets use solc's signed slt + modular wrap;
   *  oversized payloads Panic(0x41) then EMPTY-revert on calldata overrun. `validate`:
   *  value leaves revert on dirty bits (nested/struct decode) vs clean (flat value
   *  array). */
  private abiEncFromCd(
    t: JethType,
    cdPtr: string,
    dst: string,
    validate: boolean,
    out: string[],
    capEmptyRevert = false,
    // W6C: the calldata->MEMORY BIND copy of a value-leaf enum array (`const b: Color[] = a`,
    // Arr<Color,N>, Arr<Color,2>[]) copies enum words RAW (calldatacopy semantics, matching solc's
    // convert-to-memory: NO validation during the copy; the element READ / re-encode validates
    // lazily with Panic 0x21). Only honored when !validate. The RETURN echo (`return a`) keeps the
    // eager Panic-0x21 (solc's abi_encode validator_assert), i.e. enumRaw=false.
    enumRaw = false,
  ): string {
    // In a DECODE/re-encode context (abi.encode/encodeWith*/emit/error materialization, reached via
    // echoParam's forceValidate), an oversized length or memory-overflow cap is an ABI-DECODE FAILURE ->
    // revert(0, 0) (empty), matching solc. In the plain return-echo copy context it Panics 0x41 (also
    // matching solc - e.g. `return xs` for a bytes[] with an inner length >= 2^64). The calldatasize and
    // offset bounds already revert(0,0) in both; only these unsigned 2^64 caps were context-dependent.
    const capRevert = capEmptyRevert ? `revert(0, 0)` : `${this.panic()}(0x41)`;
    // a single value leaf
    if (isStaticValueType(t)) {
      const w = this.fresh();
      out.push(`let ${w} := calldataload(${cdPtr})`);
      if (validate) {
        const g = this.validateInput(t, w);
        if (g) out.push(g);
        out.push(`mstore(${dst}, ${w})`);
      } else if ((t as { enumMembers?: string[] }).enumMembers) {
        // An enum element copied whole in a RETURN echo is range-checked like an explicit
        // conversion: solc reverts Panic(0x21) on an out-of-range element during the encode.
        // W6C: a BIND copy to memory (enumRaw) stores the word RAW instead (calldatacopy
        // semantics, matching solc's convert-to-memory; the read validates lazily).
        if (!enumRaw) {
          out.push(
            `if iszero(lt(${w}, ${(t as { enumMembers: string[] }).enumMembers.length})) { ${this.panic()}(0x21) }`,
          );
        }
        out.push(`mstore(${dst}, ${w})`);
      } else {
        out.push(`mstore(${dst}, ${this.cleanCalldataElem(t, w)})`);
      }
      return '32';
    }
    // a static aggregate (struct or fixed array of static): copy each leaf word. With
    // `validate`, dirty narrow leaves revert (struct-field / nested decode); without, they
    // are cleaned/masked (a whole value-leaf fixed-array echo, matching solc decode-to-memory).
    if (isStaticType(t)) {
      for (const leaf of abiLeaves(t)) {
        const w = this.fresh();
        out.push(`let ${w} := calldataload(add(${cdPtr}, ${leaf.wordOffset * 32}))`);
        if (validate) {
          const g = this.validateInput(leaf.type, w);
          if (g) out.push(g);
          out.push(`mstore(add(${dst}, ${leaf.wordOffset * 32}), ${w})`);
        } else if ((leaf.type as { enumMembers?: string[] }).enumMembers) {
          // enum leaf in a whole-aggregate echo: Panic(0x21) on out-of-range (see the value-leaf
          // case above), not a silent mask. W6C: a BIND copy (enumRaw) stores RAW instead.
          if (!enumRaw) {
            out.push(
              `if iszero(lt(${w}, ${(leaf.type as { enumMembers: string[] }).enumMembers.length})) { ${this.panic()}(0x21) }`,
            );
          }
          out.push(`mstore(add(${dst}, ${leaf.wordOffset * 32}), ${w})`);
        } else {
          out.push(`mstore(add(${dst}, ${leaf.wordOffset * 32}), ${this.cleanCalldataElem(leaf.type, w)})`);
        }
      }
      return String(abiHeadWords(t) * 32);
    }
    // bytes / string: [len][right-padded data]
    if (isBytesLike(t)) {
      const len = this.fresh();
      out.push(`let ${len} := calldataload(${cdPtr})`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${capRevert} }`);
      const padded = this.fresh();
      out.push(`let ${padded} := and(add(${len}, 0x1f), not(0x1f))`);
      const nc = this.fresh();
      out.push(`let ${nc} := add(add(${dst}, 0x20), ${padded})`);
      out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${dst})) { ${capRevert} }`);
      out.push(`if gt(add(add(${cdPtr}, 0x20), ${len}), calldatasize()) { revert(0, 0) }`);
      out.push(`mstore(${dst}, ${len})`);
      out.push(`calldatacopy(add(${dst}, 0x20), add(${cdPtr}, 0x20), ${len})`);
      out.push(`if mod(${len}, 0x20) { mstore(add(add(${dst}, 0x20), ${len}), 0) }`);
      return `add(0x20, ${padded})`;
    }
    // dynamic array T[]: [len][ static elements inline | dynamic elements head+tail ]
    if (t.kind === 'array' && t.length === undefined) {
      const len = this.fresh();
      out.push(`let ${len} := calldataload(${cdPtr})`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${capRevert} }`);
      out.push(`mstore(${dst}, ${len})`);
      const elemRegion = this.fresh();
      out.push(`let ${elemRegion} := add(${cdPtr}, 0x20)`);
      const dstHead = this.fresh();
      out.push(`let ${dstHead} := add(${dst}, 0x20)`);
      if (isStaticType(t.element)) {
        // INLINE for BOTH a static value element AND a static struct element: abiEncFromCd is the
        // calldata->ABI encoder (its output doubles as the ABI return blob via echoParam, and as the
        // inline element block inside a parent aggregate's ABI image), so a static-struct element stays
        // INLINE here. (Cat B's POINTER-HEADED layout is a MEMORY-IMAGE concern; the calldata->memory
        // bind of a static-struct array is separately gated, so no pointer-headed consumer exists here.)
        const es = abiHeadWords(t.element) * 32;
        const nc = this.fresh();
        out.push(`let ${nc} := add(${dstHead}, mul(${len}, ${es}))`);
        out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${dstHead})) { ${capRevert} }`);
        out.push(`if gt(add(${elemRegion}, mul(${len}, ${es})), calldatasize()) { revert(0, 0) }`);
        const elemValidate = validate || !isStaticValueType(t.element);
        const i = this.fresh();
        out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
        const inner: string[] = [];
        const ecd = this.fresh();
        inner.push(`let ${ecd} := add(${elemRegion}, mul(${i}, ${es}))`);
        const edst = this.fresh();
        inner.push(`let ${edst} := add(${dstHead}, mul(${i}, ${es}))`);
        this.abiEncFromCd(t.element, ecd, edst, elemValidate, inner, capEmptyRevert, enumRaw);
        for (const l of inner) out.push('  ' + l);
        out.push('}');
        return `add(0x20, mul(${len}, ${es}))`;
      }
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dstHead}, mul(${len}, 0x20))`);
      out.push(`if or(gt(${cursor}, 0xffffffffffffffff), lt(${cursor}, ${dstHead})) { ${capRevert} }`);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
      const inner: string[] = [];
      const so = this.fresh();
      inner.push(`let ${so} := calldataload(add(${elemRegion}, mul(${i}, 0x20)))`);
      // ECHO (whole-aggregate decode-to-memory) uses solc's UNSIGNED 2^64 cap + a
      // length-word-readable check, NOT the lazy-access signed wrap.
      inner.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
      const se = this.fresh();
      inner.push(`let ${se} := add(${elemRegion}, ${so})`);
      inner.push(`if gt(add(${se}, ${cdElemHeadBytes(t.element)}), calldatasize()) { revert(0, 0) }`);
      inner.push(`mstore(add(${dstHead}, mul(${i}, 0x20)), sub(${cursor}, ${dstHead}))`);
      const sz = this.abiEncFromCd(t.element, se, cursor, true, inner, capEmptyRevert);
      inner.push(`${cursor} := add(${cursor}, ${sz})`);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
      return `sub(${cursor}, ${dst})`;
    }
    // fixed array of dynamic element Arr<dyn,N>: an N-word offset table (no length), base = dst/cdPtr
    if (t.kind === 'array' && t.length !== undefined) {
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dst}, ${t.length * 32})`);
      for (let k = 0; k < t.length; k++) {
        const so = this.fresh();
        out.push(`let ${so} := calldataload(add(${cdPtr}, ${k * 32}))`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${cdPtr}, ${so})`);
        out.push(`if gt(add(${se}, ${cdElemHeadBytes(t.element)}), calldatasize()) { revert(0, 0) }`);
        out.push(`mstore(add(${dst}, ${k * 32}), sub(${cursor}, ${dst}))`);
        const sz = this.abiEncFromCd(t.element, se, cursor, true, out, capEmptyRevert);
        out.push(`${cursor} := add(${cursor}, ${sz})`);
      }
      return `sub(${cursor}, ${dst})`;
    }
    // dynamic struct (tuple with >=1 dynamic field): head (static inline / dynamic offset) + tails
    if (t.kind === 'struct') {
      const headWords = tupleHeadWords(t);
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dst}, ${headWords * 32})`);
      let hw = 0;
      for (const f of t.fields) {
        const fb = hw * 32;
        if (!isDynamicType(f.type)) {
          this.abiEncFromCd(f.type, `add(${cdPtr}, ${fb})`, `add(${dst}, ${fb})`, true, out, capEmptyRevert);
          hw += abiHeadWords(f.type);
        } else {
          const so = this.fresh();
          out.push(`let ${so} := calldataload(add(${cdPtr}, ${fb}))`);
          out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
          const se = this.fresh();
          out.push(`let ${se} := add(${cdPtr}, ${so})`);
          out.push(`if gt(add(${se}, ${cdElemHeadBytes(f.type)}), calldatasize()) { revert(0, 0) }`);
          out.push(`mstore(add(${dst}, ${fb}), sub(${cursor}, ${dst}))`);
          const sz = this.abiEncFromCd(f.type, se, cursor, true, out, capEmptyRevert);
          out.push(`${cursor} := add(${cursor}, ${sz})`);
          hw += 1;
        }
      }
      return `sub(${cursor}, ${dst})`;
    }
    throw new UnsupportedError(`abiEncFromCd: unsupported type '${t.kind}'`);
  }

  /** abi.decode codec: decode a MEMORY-sourced ABI value of type `t` (the DATA word at memory byte
   *  `memPtr`) into a fresh memory image at `dst`. The memory analogue of abiEncFromCd: reads via
   *  mload (not calldataload), copies via mcopy (not calldatacopy), and bounds every offset/length
   *  against `blobEnd` (the absolute memory end address of the source blob, = blobData + blobLen)
   *  rather than calldatasize(). Returns a Yul expr for the byte size written into `dst`. Byte-identical
   *  to solc's abi.decode-from-memory: an oversized inner length / memory-alloc overflow Panics(0x41)
   *  (the memory-decode cap), while an out-of-bounds offset / a length running past the blob reverts
   *  EMPTY (revert(0, 0)). Value leaves are always VALIDATED (dirty narrow bits revert empty, like
   *  solc's decode of a tuple component / array element). Compile-time recursion over `t` => unbounded
   *  nesting; array lengths drive runtime loops. */
  /** ABI-encode a NESTED VALUE-array memory image into the canonical ABI blob. The memory image is
   *  JETH's own nested-array representation (built by the arrayLit / new Array lowering and the index/
   *  assign paths): a value/static-element array is `[len][inline element words]` (or, for a static
   *  fixed array, just the inline words, no length); a dynamic-ELEMENT array stores, per element, an
   *  ABSOLUTE memory pointer to that element's own image. This encoder reads the image (mload, following
   *  the absolute pointers) and writes the ABI form at `dst`, where each dynamic element becomes a
   *  RELATIVE offset + tail (solc's canonical encoding). Returns a Yul expr for the bytes written.
   *  Only the value-leaf array nestings the analyzer accepts reach here (no bytes/string/struct leaves),
   *  so no length/offset validation is needed: the image was built from trusted literals / zero-init. */
  private abiEncFromMem(t: JethType, memPtr: string, dst: string, ctx: LowerCtx, out: string[]): string {
    // Residual B3: a DYNAMIC-field struct leaf (an element of a P[] image, P with bytes/string/dyn-array
    // fields). memPtr is the element's pointer-headed dyn-struct image; encode it as a self-contained ABI
    // dynamic tuple at `dst` (value fields inline, dynamic fields head OFFSET relative to THIS tuple +
    // tail), reusing the verified whole-struct tuple encoder. Returns the encoded byte size.
    if (t.kind === 'struct' && isDynamicType(t)) {
      return this.abiEncDynStructFromMem(t, memPtr, dst, ctx, out);
    }
    // Residual B2: a bytes/string leaf (an element of a bytes[]/string[] image). memPtr is the blob's
    // absolute pointer ([len][right-padded data]); the ABI tail is [len][data padded to 32]. Returns the
    // encoded byte size. (Reached via the dynamic-element recursion below for bytes[]/string[].)
    if (isBytesLike(t)) {
      const len = this.fresh();
      out.push(`let ${len} := mload(${memPtr})`);
      out.push(`mstore(${dst}, ${len})`);
      const padded = this.fresh();
      out.push(`let ${padded} := and(add(${len}, 0x1f), not(0x1f))`);
      out.push(`mcopy(add(${dst}, 0x20), add(${memPtr}, 0x20), ${len})`);
      // zero the partial last word so trailing ABI padding is clean (the blob is tail-zeroed on build,
      // but a sub-view alias may not be; mirror the storage/calldata bytes return encoder).
      out.push(`if mod(${len}, 0x20) { mstore(add(add(${dst}, 0x20), ${len}), 0) }`);
      return `add(0x20, ${padded})`;
    }
    if (t.kind !== 'array') {
      // a value/static leaf: copy each ABI head word inline (abiHeadWords words, contiguous).
      const hw = abiHeadWords(t);
      for (let k = 0; k < hw; k++) {
        const off = k * 32;
        out.push(`mstore(add(${dst}, ${off}), mload(add(${memPtr}, ${off})))`);
      }
      return String(hw * 32);
    }
    // a STATIC VALUE array (fixed length, value leaves: Arr<u256,N>, Arr<Arr<u256,2>,2>): the image is
    // abiHeadWords(t) contiguous inline words; copy them verbatim (no offsets, no length). A static
    // STRUCT-leaf fixed array (Batch A: Arr<P,N>) is STATIC too but POINTER-HEADED in memory, so it must
    // NOT be copied verbatim - it falls to the FIXED-outer pointer-headed branch below (flatten per element).
    if (isStaticType(t) && !isStaticStructFixedLeafArray(t)) {
      const hw = abiHeadWords(t);
      const i = this.fresh();
      // W6C: an ENUM leaf encodes out of memory with a range check (Panic 0x21, solc's
      // validator_assert) - the image may hold RAW dirty words from a calldata bind copy.
      const en = t.kind === 'array' ? this.enumCount(this.arrayLeaf(t)) : undefined;
      out.push(`for { let ${i} := 0 } lt(${i}, ${hw * 32}) { ${i} := add(${i}, 0x20) } {`);
      if (en !== undefined) out.push(`  if iszero(lt(mload(add(${memPtr}, ${i})), ${en})) { ${this.panic()}(0x21) }`);
      out.push(`  mstore(add(${dst}, ${i}), mload(add(${memPtr}, ${i})))`);
      out.push('}');
      return String(hw * 32);
    }
    if (t.length === undefined) {
      // a DYNAMIC array T[]. Image: [len] then, per element, either an inline element block (static
      // element) or an absolute pointer (dynamic element). ABI: [len][ elements inline | offset table + tails ].
      const len = this.fresh();
      out.push(`let ${len} := mload(${memPtr})`);
      out.push(`mstore(${dst}, ${len})`);
      const srcHead = this.fresh();
      out.push(`let ${srcHead} := add(${memPtr}, 0x20)`);
      const dstHead = this.fresh();
      out.push(`let ${dstHead} := add(${dst}, 0x20)`);
      if (isStaticType(t.element) && !isPointerHeadedStaticElem(t.element)) {
        // a STATIC VALUE element (value word or fixed-static-value-array): the image stores the element
        // inline; copy abiHeadWords(element) words per element straight across.
        const es = abiHeadWords(t.element) * 32;
        const i = this.fresh();
        // W6C: ENUM elements range-check on the way out of memory (Panic 0x21, see above).
        const en = this.enumCount(this.arrayLeaf(t.element));
        out.push(`for { let ${i} := 0 } lt(${i}, mul(${len}, ${es})) { ${i} := add(${i}, 0x20) } {`);
        if (en !== undefined) out.push(`  if iszero(lt(mload(add(${srcHead}, ${i})), ${en})) { ${this.panic()}(0x21) }`);
        out.push(`  mstore(add(${dstHead}, ${i}), mload(add(${srcHead}, ${i})))`);
        out.push('}');
        return `add(0x20, mul(${len}, ${es}))`;
      }
      if (isPointerHeadedStaticElem(t.element)) {
        // Cat B / Batch A: a STATIC-STRUCT element (P[]) or a STATIC fixed-struct-array element (Arr<P,N>[])
        // is POINTER-HEADED in memory but the ABI output stays INLINE (a static element occupies its
        // abiHeadWords words inline, no offset table - exactly as solc encodes it). Per element follow the
        // absolute pointer in the image head word, then write its es inline bytes at the inline ABI slot.
        // A FLAT static struct image already IS its inline ABI bytes -> copy es words verbatim. A nested
        // pointer-headed element (Arr<P,N>) needs the recursive codec to FLATTEN its inner pointer words.
        const es = abiHeadWords(t.element) * 32;
        const nestedPtr = t.element.kind === 'array'; // Arr<P,N> element: inner image is itself pointer-headed
        const i = this.fresh();
        out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
        const inner: string[] = [];
        const ip = this.fresh();
        inner.push(`let ${ip} := mload(add(${srcHead}, mul(${i}, 0x20)))`); // absolute ptr to element image
        const edst = this.fresh();
        inner.push(`let ${edst} := add(${dstHead}, mul(${i}, ${es}))`);
        if (nestedPtr) this.abiEncFromMem(t.element, ip, edst, ctx, inner);
        else for (let k = 0; k < es / 32; k++) inner.push(`mstore(add(${edst}, ${k * 32}), mload(add(${ip}, ${k * 32})))`);
        for (const l of inner) out.push('  ' + l);
        out.push('}');
        return `add(0x20, mul(${len}, ${es}))`;
      }
      // a DYNAMIC element: offset table of `len` words then the inner tails, each inner reached via
      // the absolute pointer stored in the image head word.
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dstHead}, mul(${len}, 0x20))`);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
      const inner: string[] = [];
      const ip = this.fresh();
      inner.push(`let ${ip} := mload(add(${srcHead}, mul(${i}, 0x20)))`); // absolute ptr to inner image
      inner.push(`mstore(add(${dstHead}, mul(${i}, 0x20)), sub(${cursor}, ${dstHead}))`);
      const sz = this.abiEncFromMem(t.element, ip, cursor, ctx, inner);
      inner.push(`${cursor} := add(${cursor}, ${sz})`);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
      return `sub(${cursor}, ${dst})`;
    }
    // Batch A: a FIXED array (Arr<P,N>) whose element is POINTER-HEADED STATIC (a static struct, or a
    // nested static-struct array Arr<P,M>). The image is N absolute-pointer words (no [len] header); the
    // ABI output is N inline es-word blocks (a static type is encoded INLINE, no offset table). Per element
    // follow the abs ptr and write its inline bytes at k*es: a flat static struct image IS its inline ABI
    // bytes (copy verbatim); a nested pointer-headed element (Arr<P,M>) needs the recursive codec to flatten.
    if (isPointerHeadedStaticElem(t.element)) {
      const es = abiHeadWords(t.element) * 32;
      const nestedPtr = t.element.kind === 'array';
      for (let k = 0; k < t.length; k++) {
        const ip = this.fresh();
        out.push(`let ${ip} := mload(add(${memPtr}, ${k * 32}))`); // absolute ptr to element image
        const edst = k === 0 ? dst : `add(${dst}, ${k * es})`;
        if (nestedPtr) this.abiEncFromMem(t.element, ip, edst, ctx, out);
        else for (let w = 0; w < es / 32; w++) out.push(`mstore(add(${edst}, ${w * 32}), mload(add(${ip}, ${w * 32})))`);
      }
      return String(t.length * es);
    }
    // a FIXED array of a DYNAMIC element (Arr<u256[],N>): no length word; an N-word offset table
    // (relative to dst) then the inner tails, each inner reached via the absolute pointer stored in
    // the image's N pointer words.
    const cursor = this.fresh();
    out.push(`let ${cursor} := add(${dst}, ${t.length * 32})`);
    for (let k = 0; k < t.length; k++) {
      const ip = this.fresh();
      out.push(`let ${ip} := mload(add(${memPtr}, ${k * 32}))`); // absolute ptr to inner image
      out.push(`mstore(add(${dst}, ${k * 32}), sub(${cursor}, ${dst}))`);
      const sz = this.abiEncFromMem(t.element, ip, cursor, ctx, out);
      out.push(`${cursor} := add(${cursor}, ${sz})`);
    }
    return `sub(${cursor}, ${dst})`;
  }

  /** Encode a DYNAMIC-field struct from its pointer-headed memory image (`memPtr`) into a self-contained
   *  ABI dynamic tuple at `dst` (Residual B3: a P[] element). Value fields stay inline in the head; each
   *  dynamic field gets a head OFFSET word relative to THIS tuple's start, then its tail. Reuses the
   *  verified whole-struct tuple encoder (encodeTupleInto) with a 'mem' source. Returns the byte size. */
  private abiEncDynStructFromMem(
    struct: JethType & { kind: 'struct' },
    memPtr: string,
    dst: string,
    ctx: LowerCtx,
    out: string[],
  ): string {
    const src: TupleSrc = { kind: 'mem', headPtr: memPtr };
    // PRE-PASS: materialize each dynamic field's source DynRef from the image (mirrors the whole-struct
    // encoders), so the dyn-field queue feeds encodeTupleInto in field order. materializeFixedTails =
    // false: `dst` is a caller-provided cursor (its enclosing blob pointer is already captured), so the
    // pre-pass MUST NOT allocate; a fixed-outer field queues its bare image pointer and is transcoded
    // in place at the cursor (a memory source's pre-pass allocates nothing - the load-bearing invariant).
    const queue: DynRef[] = [];
    this.collectTupleDyn(struct, src, queue, ctx, out, false);
    let qi = 0;
    const nextRef = (): DynRef => queue[qi++]!;
    const end = this.encodeTupleInto(struct, src, dst, ctx, out, nextRef);
    return `sub(${end}, ${dst})`;
  }

  private abiDecFromMem(t: JethType, memPtr: string, dst: string, blobEnd: string, out: string[]): string {
    const cap = `${this.panic()}(0x41)`;
    // a single value leaf: one word, validated.
    if (isStaticValueType(t)) {
      const w = this.fresh();
      out.push(`let ${w} := mload(${memPtr})`);
      const g = this.validateInput(t, w);
      if (g) out.push(g);
      out.push(`mstore(${dst}, ${w})`);
      return '32';
    }
    // a static aggregate (struct / fixed array of static VALUE leaves): copy each leaf word, validated.
    // A static STRUCT-leaf fixed array (Batch A: Arr<P,N>) is STATIC but POINTER-HEADED in memory; it must
    // NOT be decoded as flat inline words - it falls to the FIXED-outer pointer-headed branch below.
    if (isStaticType(t) && !isStaticStructFixedLeafArray(t)) {
      for (const leaf of abiLeaves(t)) {
        const w = this.fresh();
        out.push(`let ${w} := mload(add(${memPtr}, ${leaf.wordOffset * 32}))`);
        const g = this.validateInput(leaf.type, w);
        if (g) out.push(g);
        out.push(`mstore(add(${dst}, ${leaf.wordOffset * 32}), ${w})`);
      }
      return String(abiHeadWords(t) * 32);
    }
    // bytes / string: [len][right-padded data].
    if (isBytesLike(t)) {
      const len = this.fresh();
      out.push(`let ${len} := mload(${memPtr})`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${cap} }`);
      const padded = this.fresh();
      out.push(`let ${padded} := and(add(${len}, 0x1f), not(0x1f))`);
      const nc = this.fresh();
      out.push(`let ${nc} := add(add(${dst}, 0x20), ${padded})`);
      out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${dst})) { ${cap} }`);
      out.push(`if gt(add(add(${memPtr}, 0x20), ${len}), ${blobEnd}) { revert(0, 0) }`);
      out.push(`mstore(${dst}, ${len})`);
      out.push(`mcopy(add(${dst}, 0x20), add(${memPtr}, 0x20), ${len})`);
      out.push(`if mod(${len}, 0x20) { mstore(add(add(${dst}, 0x20), ${len}), 0) }`);
      return `add(0x20, ${padded})`;
    }
    // dynamic array T[]: [len][ static elements inline | dynamic elements head+tail ].
    if (t.kind === 'array' && t.length === undefined) {
      const len = this.fresh();
      out.push(`let ${len} := mload(${memPtr})`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${cap} }`);
      out.push(`mstore(${dst}, ${len})`);
      const elemRegion = this.fresh();
      out.push(`let ${elemRegion} := add(${memPtr}, 0x20)`);
      const dstHead = this.fresh();
      out.push(`let ${dstHead} := add(${dst}, 0x20)`);
      if (isStaticType(t.element) && !isPointerHeadedStaticElem(t.element)) {
        const es = abiHeadWords(t.element) * 32;
        const nc = this.fresh();
        out.push(`let ${nc} := add(${dstHead}, mul(${len}, ${es}))`);
        out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${dstHead})) { ${cap} }`);
        out.push(`if gt(add(${elemRegion}, mul(${len}, ${es})), ${blobEnd}) { revert(0, 0) }`);
        const i = this.fresh();
        out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
        const inner: string[] = [];
        const ecd = this.fresh();
        inner.push(`let ${ecd} := add(${elemRegion}, mul(${i}, ${es}))`);
        const edst = this.fresh();
        inner.push(`let ${edst} := add(${dstHead}, mul(${i}, ${es}))`);
        this.abiDecFromMem(t.element, ecd, edst, blobEnd, inner);
        for (const l of inner) out.push('  ' + l);
        out.push('}');
        return `add(0x20, mul(${len}, ${es}))`;
      }
      if (isPointerHeadedStaticElem(t.element)) {
        // Cat B: a STATIC-STRUCT element (P[]) is POINTER-HEADED: the [len] header + a len-word
        // ABSOLUTE-pointer table go INTO `dst`; each per-element image is allocated FRESH past the
        // parent block via 0x40 (the self-managed allocator inside abiDecFromMemToImage's struct
        // self-branch). The returned size spans the table only; per-element images live PAST the free
        // pointer abiDecFromMemToImage leaves bumped, so the caller's `mstore(0x40, add(dst, sz))` is
        // NEVER smaller than that free pointer for any reachable caller (a top-level / nested-dynamic
        // P[] is rerouted to abiDecFromMemToImage, which self-manages 0x40 and does NOT advance by a
        // size). Source layout is still INLINE ABI (element stride es), bounds/cap order unchanged.
        const es = abiHeadWords(t.element) * 32;
        const tableEnd = this.fresh();
        out.push(`let ${tableEnd} := add(${dstHead}, mul(${len}, 0x20))`);
        out.push(`if or(gt(${tableEnd}, 0xffffffffffffffff), lt(${tableEnd}, ${dstHead})) { ${cap} }`);
        out.push(`if gt(add(${elemRegion}, mul(${len}, ${es})), ${blobEnd}) { revert(0, 0) }`);
        out.push(`mstore(0x40, ${tableEnd})`); // claim the table; per-element images alloc PAST it
        const i = this.fresh();
        out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
        const inner: string[] = [];
        const esrc = this.fresh();
        inner.push(`let ${esrc} := add(${elemRegion}, mul(${i}, ${es}))`);
        const ip = this.fresh();
        inner.push(`let ${ip} := ${this.abiDecFromMemToImage(t.element, esrc, blobEnd, inner)}`);
        inner.push(`mstore(add(${dstHead}, mul(${i}, 0x20)), ${ip})`);
        for (const l of inner) out.push('  ' + l);
        out.push('}');
        return `add(0x20, mul(${len}, 0x20))`;
      }
      // dynamic element (bytes/string/...): an N-word offset table relative to elemRegion, plus tails.
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dstHead}, mul(${len}, 0x20))`);
      out.push(`if or(gt(${cursor}, 0xffffffffffffffff), lt(${cursor}, ${dstHead})) { ${cap} }`);
      // The SOURCE offset table (len words) must fit in the blob, exactly as the static-element path
      // checks above: solc reverts EMPTY (data out of bounds) when it does not. This comes AFTER the
      // allocation-size cap so an oversized length still Panics 0x41 (solc allocates the array - which
      // Panics on the huge size - BEFORE its data-bounds revert). mul cannot overflow here: the cursor
      // cap already rejected any len large enough to overflow (len <= 2^64-1 from the cap above too).
      out.push(`if gt(add(${elemRegion}, mul(${len}, 0x20)), ${blobEnd}) { revert(0, 0) }`);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
      const inner: string[] = [];
      const so = this.fresh();
      inner.push(`let ${so} := mload(add(${elemRegion}, mul(${i}, 0x20)))`);
      inner.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
      const se = this.fresh();
      inner.push(`let ${se} := add(${elemRegion}, ${so})`);
      inner.push(`if gt(add(${se}, ${cdElemHeadBytes(t.element)}), ${blobEnd}) { revert(0, 0) }`);
      inner.push(`mstore(add(${dstHead}, mul(${i}, 0x20)), sub(${cursor}, ${dstHead}))`);
      const sz = this.abiDecFromMem(t.element, se, cursor, blobEnd, inner);
      inner.push(`${cursor} := add(${cursor}, ${sz})`);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
      return `sub(${cursor}, ${dst})`;
    }
    // Batch A: a FIXED array (Arr<P,N>) of a POINTER-HEADED STATIC element (static struct, or a nested
    // static-struct array). The SOURCE is N inline es-word blocks (es = abiHeadWords(element)*32, NO offset
    // table, NO length). The IMAGE at `dst` is N absolute-pointer words, each -> a fresh per-element image
    // (decoded via abiDecFromMemToImage, which self-allocates past 0x40). The source data-bounds check
    // (truncated -> empty revert) mirrors the dynamic-outer pointer branch; there is no allocation cap for
    // the fixed N table (it is a compile-time-constant N words at dst, the caller already sized it).
    if (t.kind === 'array' && t.length !== undefined && isPointerHeadedStaticElem(t.element)) {
      const es = abiHeadWords(t.element) * 32;
      out.push(`if gt(add(${memPtr}, ${t.length * es}), ${blobEnd}) { revert(0, 0) }`);
      for (let k = 0; k < t.length; k++) {
        const esrc = k === 0 ? memPtr : `add(${memPtr}, ${k * es})`;
        const ip = this.fresh();
        out.push(`let ${ip} := ${this.abiDecFromMemToImage(t.element, esrc, blobEnd, out)}`);
        out.push(`mstore(add(${dst}, ${k * 32}), ${ip})`);
      }
      return String(t.length * 32);
    }
    // fixed array of dynamic element Arr<dyn,N>: an N-word offset table (no length), base = dst/memPtr.
    if (t.kind === 'array' && t.length !== undefined) {
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dst}, ${t.length * 32})`);
      for (let k = 0; k < t.length; k++) {
        const so = this.fresh();
        out.push(`let ${so} := mload(add(${memPtr}, ${k * 32}))`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${memPtr}, ${so})`);
        out.push(`if gt(add(${se}, ${cdElemHeadBytes(t.element)}), ${blobEnd}) { revert(0, 0) }`);
        out.push(`mstore(add(${dst}, ${k * 32}), sub(${cursor}, ${dst}))`);
        const sz = this.abiDecFromMem(t.element, se, cursor, blobEnd, out);
        out.push(`${cursor} := add(${cursor}, ${sz})`);
      }
      return `sub(${cursor}, ${dst})`;
    }
    // dynamic struct (tuple with >=1 dynamic field): head (static inline / dynamic offset) + tails.
    if (t.kind === 'struct') {
      const headWords = tupleHeadWords(t);
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dst}, ${headWords * 32})`);
      let hw = 0;
      for (const f of t.fields) {
        const fb = hw * 32;
        if (!isDynamicType(f.type)) {
          this.abiDecFromMem(f.type, `add(${memPtr}, ${fb})`, `add(${dst}, ${fb})`, blobEnd, out);
          hw += abiHeadWords(f.type);
        } else {
          const so = this.fresh();
          out.push(`let ${so} := mload(add(${memPtr}, ${fb}))`);
          out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
          const se = this.fresh();
          out.push(`let ${se} := add(${memPtr}, ${so})`);
          out.push(`if gt(add(${se}, ${cdElemHeadBytes(f.type)}), ${blobEnd}) { revert(0, 0) }`);
          out.push(`mstore(add(${dst}, ${fb}), sub(${cursor}, ${dst}))`);
          const sz = this.abiDecFromMem(f.type, se, cursor, blobEnd, out);
          out.push(`${cursor} := add(${cursor}, ${sz})`);
          hw += 1;
        }
      }
      return `sub(${cursor}, ${dst})`;
    }
    throw new UnsupportedError(`abiDecFromMem: unsupported type '${t.kind}'`);
  }

  /** Residual C: decode a MEMORY-sourced ABI value of type `t` (the DATA word at `memPtr`) into a fresh
   *  ALLOCATED memory image in Residual B's ABSOLUTE-POINTER layout, returning the image pointer. The
   *  decode twin of abiEncFromMem and the inverse of buildNestedMemArrayLit: where abiDecFromMem writes
   *  the STANDARD ABI image (a dynamic element becomes a RELATIVE offset into a contiguous block), this
   *  writes B's image (a dynamic element becomes an ABSOLUTE pointer to a fresh sub-image), which is what
   *  B's memory-array readers mload. Keeps EXACTLY the bounds/cap/payload-fit checks abiDecFromMem does,
   *  so a truncated/malformed blob reverts BYTE-IDENTICALLY to solc's memory decode. Used for C1
   *  (u256[][] and other nested value arrays) and C3 (bytes[]/string[]); a STATIC element (C2's P[]) is
   *  decoded inline via abiDecFromMem (no pointers, so its standard image already matches B's). */
  private abiDecFromMemToImage(t: JethType, memPtr: string, blobEnd: string, out: string[]): string {
    const cap = `${this.panic()}(0x41)`;
    // a bytes/string leaf: alloc a [len][data] blob, return its absolute pointer.
    if (isBytesLike(t)) {
      const len = this.fresh();
      out.push(`let ${len} := mload(${memPtr})`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${cap} }`);
      const padded = this.fresh();
      out.push(`let ${padded} := and(add(${len}, 0x1f), not(0x1f))`);
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      const nc = this.fresh();
      out.push(`let ${nc} := add(add(${ptr}, 0x20), ${padded})`);
      out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${ptr})) { ${cap} }`);
      out.push(`if gt(add(add(${memPtr}, 0x20), ${len}), ${blobEnd}) { revert(0, 0) }`);
      out.push(`mstore(${ptr}, ${len})`);
      out.push(`mcopy(add(${ptr}, 0x20), add(${memPtr}, 0x20), ${len})`);
      out.push(`if mod(${len}, 0x20) { mstore(add(add(${ptr}, 0x20), ${len}), 0) }`);
      out.push(`mstore(0x40, ${nc})`);
      return ptr;
    }
    // a STATIC element (value / static struct / static VALUE fixed array): its image is the abiHeadWords(t)
    // inline words; decode them inline (validated) into a fresh block, return the block pointer. (B's
    // image stores a static element inline; for a static-element array this branch is not used, but it
    // keeps the recursion total.) A static STRUCT-leaf fixed array (Batch A: Arr<P,N>) is STATIC but its
    // IMAGE is POINTER-HEADED, so it is excluded here and handled by the FIXED-outer branch below.
    if (isStaticType(t) && !isStaticStructFixedLeafArray(t)) {
      const hw = abiHeadWords(t);
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      out.push(`mstore(0x40, add(${ptr}, ${hw * 32}))`);
      this.abiDecFromMem(t, memPtr, ptr, blobEnd, out);
      return ptr;
    }
    // a dynamic array T[]: alloc [len] + an len-word table; each element word holds either an inline
    // block (static element) or an ABSOLUTE pointer to a fresh element sub-image (dynamic element).
    if (t.kind === 'array' && t.length === undefined) {
      const len = this.fresh();
      out.push(`let ${len} := mload(${memPtr})`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${cap} }`);
      const elemRegion = this.fresh();
      out.push(`let ${elemRegion} := add(${memPtr}, 0x20)`);
      if (isStaticType(t.element) && !isPointerHeadedStaticElem(t.element)) {
        // a STATIC VALUE element (Arr<u256,N>[]): inline blocks, exactly abiDecFromMem's static-element
        // layout (the image == the standard ABI image for a static value element). Decode inline.
        const es = abiHeadWords(t.element) * 32;
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(0x40)`);
        const nc = this.fresh();
        out.push(`let ${nc} := add(add(${ptr}, 0x20), mul(${len}, ${es}))`);
        out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${ptr})) { ${cap} }`);
        out.push(`if gt(add(${elemRegion}, mul(${len}, ${es})), ${blobEnd}) { revert(0, 0) }`);
        out.push(`mstore(${ptr}, ${len})`);
        out.push(`mstore(0x40, ${nc})`);
        const dstHead = this.fresh();
        out.push(`let ${dstHead} := add(${ptr}, 0x20)`);
        const i = this.fresh();
        out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
        const inner: string[] = [];
        const ecd = this.fresh();
        inner.push(`let ${ecd} := add(${elemRegion}, mul(${i}, ${es}))`);
        const edst = this.fresh();
        inner.push(`let ${edst} := add(${dstHead}, mul(${i}, ${es}))`);
        this.abiDecFromMem(t.element, ecd, edst, blobEnd, inner);
        for (const l of inner) out.push('  ' + l);
        out.push('}');
        return ptr;
      }
      if (isPointerHeadedStaticElem(t.element)) {
        // Cat B: a STATIC-STRUCT element (P[]). The SOURCE is still INLINE ABI (element stride es =
        // abiHeadWords(P)*32, NO offset table), but the in-memory IMAGE is now POINTER-HEADED: alloc
        // [len] + a len-word ABSOLUTE-pointer table, then per element decode the inline source block
        // (the self-branch allocs+validates an es-word element image and returns its pointer) and store
        // that pointer. Allocation CAP (oversized -> Panic 0x41) BEFORE the source data-bounds revert
        // (truncated -> empty), matching the inline path's revert ordering byte-for-byte.
        const es = abiHeadWords(t.element) * 32;
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(0x40)`);
        const tableEnd = this.fresh();
        out.push(`let ${tableEnd} := add(add(${ptr}, 0x20), mul(${len}, 0x20))`);
        out.push(`if or(gt(${tableEnd}, 0xffffffffffffffff), lt(${tableEnd}, ${ptr})) { ${cap} }`);
        out.push(`if gt(add(${elemRegion}, mul(${len}, ${es})), ${blobEnd}) { revert(0, 0) }`);
        out.push(`mstore(${ptr}, ${len})`);
        out.push(`mstore(0x40, ${tableEnd})`); // claim the table; per-element images alloc PAST it
        const dstHead = this.fresh();
        out.push(`let ${dstHead} := add(${ptr}, 0x20)`);
        const i = this.fresh();
        out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
        const inner: string[] = [];
        const esrc = this.fresh();
        inner.push(`let ${esrc} := add(${elemRegion}, mul(${i}, ${es}))`);
        const ip = this.fresh();
        inner.push(`let ${ip} := ${this.abiDecFromMemToImage(t.element, esrc, blobEnd, inner)}`);
        inner.push(`mstore(add(${dstHead}, mul(${i}, 0x20)), ${ip})`);
        for (const l of inner) out.push('  ' + l);
        out.push('}');
        return ptr;
      }
      // a DYNAMIC element (u256[] inner, bytes/string): [len] + an len-word ABSOLUTE-pointer table.
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      const tableEnd = this.fresh();
      out.push(`let ${tableEnd} := add(add(${ptr}, 0x20), mul(${len}, 0x20))`);
      out.push(`if or(gt(${tableEnd}, 0xffffffffffffffff), lt(${tableEnd}, ${ptr})) { ${cap} }`);
      // The SOURCE offset table (len words) must fit in the blob, exactly as the static-element path
      // above checks: solc reverts EMPTY (data out of bounds) when it does not. AFTER the allocation
      // cap so an oversized length still Panics 0x41 (solc allocates the array - Panicking on the size -
      // BEFORE its data-bounds revert). mul cannot overflow: the table cap already rejected any such len.
      out.push(`if gt(add(${elemRegion}, mul(${len}, 0x20)), ${blobEnd}) { revert(0, 0) }`);
      out.push(`mstore(${ptr}, ${len})`);
      out.push(`mstore(0x40, ${tableEnd})`); // claim the table; sub-images alloc PAST it
      const dstHead = this.fresh();
      out.push(`let ${dstHead} := add(${ptr}, 0x20)`);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
      const inner: string[] = [];
      const so = this.fresh();
      inner.push(`let ${so} := mload(add(${elemRegion}, mul(${i}, 0x20)))`);
      inner.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
      const se = this.fresh();
      inner.push(`let ${se} := add(${elemRegion}, ${so})`);
      inner.push(`if gt(add(${se}, ${cdElemHeadBytes(t.element)}), ${blobEnd}) { revert(0, 0) }`);
      const ip = this.fresh();
      inner.push(`let ${ip} := ${this.abiDecFromMemToImage(t.element, se, blobEnd, inner)}`);
      inner.push(`mstore(add(${dstHead}, mul(${i}, 0x20)), ${ip})`);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
      return ptr;
    }
    // Batch A: a FIXED array (Arr<P,N>) of a POINTER-HEADED STATIC element (static struct, or a nested
    // static-struct array). The SOURCE is N inline es-word blocks (es = abiHeadWords(element)*32, NO offset
    // table, NO length); the IMAGE is N absolute-pointer words (no [len] header), each -> a fresh per-element
    // image. Claim the N-word table first (sub-images alloc PAST it); source data-bounds check up front
    // (truncated -> empty revert), mirroring the dynamic-outer pointer branch's ordering.
    if (t.kind === 'array' && t.length !== undefined && isPointerHeadedStaticElem(t.element)) {
      const es = abiHeadWords(t.element) * 32;
      out.push(`if gt(add(${memPtr}, ${t.length * es}), ${blobEnd}) { revert(0, 0) }`);
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      out.push(`mstore(0x40, add(${ptr}, ${t.length * 32}))`); // claim the table; sub-images alloc PAST it
      for (let k = 0; k < t.length; k++) {
        const esrc = k === 0 ? memPtr : `add(${memPtr}, ${k * es})`;
        const ip = this.fresh();
        out.push(`let ${ip} := ${this.abiDecFromMemToImage(t.element, esrc, blobEnd, out)}`);
        out.push(`mstore(add(${ptr}, ${k * 32}), ${ip})`);
      }
      return ptr;
    }
    // a FIXED array of a DYNAMIC element (Arr<u256[],N>): N absolute-pointer words, no length header.
    if (t.kind === 'array' && t.length !== undefined) {
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      out.push(`mstore(0x40, add(${ptr}, ${t.length * 32}))`); // claim the table; sub-images alloc PAST it
      for (let k = 0; k < t.length; k++) {
        const so = this.fresh();
        out.push(`let ${so} := mload(add(${memPtr}, ${k * 32}))`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${memPtr}, ${so})`);
        out.push(`if gt(add(${se}, ${cdElemHeadBytes(t.element)}), ${blobEnd}) { revert(0, 0) }`);
        const ip = this.fresh();
        out.push(`let ${ip} := ${this.abiDecFromMemToImage(t.element, se, blobEnd, out)}`);
        out.push(`mstore(add(${ptr}, ${k * 32}), ${ip})`);
      }
      return ptr;
    }
    // Residual B3: a DYNAMIC-field struct element (a P[] element, P with bytes/string/dyn value-array
    // fields). memPtr is the element tuple's start; decode it into a fresh pointer-headed dyn-struct
    // image (value fields inline + validated, dynamic fields a head pointer to a freshly-decoded blob/
    // array) via the SAME memory-blob decoder the top-level abi.decode(b, P) path uses (identical solc
    // revert semantics: OOB offset/length -> revert(0,0), oversized alloc -> Panic 0x41).
    if (t.kind === 'struct' && isDynamicType(t)) {
      return this.buildDynStructFromMemBlob(t, memPtr, blobEnd, out);
    }
    throw new UnsupportedError(`abiDecFromMemToImage: unsupported type '${t.kind}'`);
  }

  /** The CALLDATA twin of abiDecFromMemToImage: decodes an ABI tail at calldata offset `cdPtr` into a
   *  fresh pointer-headed memory IMAGE and returns its absolute pointer. Mechanical mirror of the mem
   *  twin: calldataload for source reads, calldatacopy for the bytes/string payload, and calldatasize()
   *  as the source data-bounds limit everywhere (the mem twin uses `blobEnd`). PARITY (load-bearing):
   *  the allocation CAP `panic(0x41)` (oversized length / alloc overflow) fires BEFORE the source
   *  data-bounds `revert(0, 0)` (truncated payload), exactly as the mem twin and solc's calldata
   *  tuple-member decode. Used only by buildDynStructFromCalldata's leaf-array branch.
   *
   *  PARITY NOTE (the allocation `cap` is caller-selected, default revert(0, 0)):
   *   - buildDynStructFromCalldata's leaf-array branch (a constructor field built FROM a calldata struct
   *     param) keeps the DEFAULT revert(0, 0) cap, matching solc's calldata-aggregate decode there.
   *   - the cd-to-mem-copy cluster (a WHOLE calldata reference-element array DEEP-COPIED into a memory
   *     local, `let row: bytes[] = a`) passes cap = panic(0x41): solc's calldata->memory deep copy hits
   *     the MEMORY allocation guard on an oversized inner length / alloc overflow exactly like abi.decode /
   *     the mem twin (empirically verified vs solc 0.8.35: inner len 2^64-1 -> Panic 0x41). Truncated /
   *     OOB source ALWAYS empty-reverts (revert(0, 0)) regardless of cap, like solc. */
  private abiDecFromCdToImage(
    t: JethType,
    cdPtr: string,
    out: string[],
    cap = `revert(0, 0)`,
    // W6C: TRUE when this (sub-)copy was reached through an OFFSET TABLE (a dynamic element /
    // fixed-outer-of-dynamic level): solc's calldata->memory copy of such levels is abi_decode
    // flavored and VALIDATES every value leaf (EMPTY revert on a dirty uintN/bool/... AND on an
    // out-of-range enum) - verified vs 0.8.35 (u8[][]/Color[][] binds revert empty eagerly).
    // FALSE (default) for the outer CONTIGUOUS level: raw calldatacopy semantics (non-enum leaves
    // masked, enum words copied RAW and validated lazily at the read - Panic 0x21).
    forceValidate = false,
  ): string {
    // a bytes/string leaf: alloc a [len][data] blob, return its absolute pointer.
    if (isBytesLike(t)) {
      const len = this.fresh();
      out.push(`let ${len} := calldataload(${cdPtr})`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${cap} }`);
      const padded = this.fresh();
      out.push(`let ${padded} := and(add(${len}, 0x1f), not(0x1f))`);
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      const nc = this.fresh();
      out.push(`let ${nc} := add(add(${ptr}, 0x20), ${padded})`);
      out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${ptr})) { ${cap} }`);
      out.push(`if gt(add(add(${cdPtr}, 0x20), ${len}), calldatasize()) { revert(0, 0) }`);
      out.push(`mstore(${ptr}, ${len})`);
      out.push(`calldatacopy(add(${ptr}, 0x20), add(${cdPtr}, 0x20), ${len})`);
      out.push(`if mod(${len}, 0x20) { mstore(add(add(${ptr}, 0x20), ${len}), 0) }`);
      out.push(`mstore(0x40, ${nc})`);
      return ptr;
    }
    // a STATIC element (value / static struct / static VALUE fixed array): its image is the abiHeadWords(t)
    // inline words; decode them inline (validated) into a fresh block, return the block pointer. A static
    // STRUCT-leaf fixed array (Arr<P,N>) is STATIC but its IMAGE is POINTER-HEADED, so it is excluded here
    // and handled by the FIXED-outer branch below.
    if (isStaticType(t) && !isStaticStructFixedLeafArray(t)) {
      const hw = abiHeadWords(t);
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      out.push(`mstore(0x40, add(${ptr}, ${hw * 32}))`);
      // a calldata->memory copy MASKS value leaves (a fixed value array Arr<u256,N> / Arr<address,N>),
      // matching solc's copy semantics (dirty narrow leaves are cleaned, not reverted); a static struct
      // still validates its fields (validate stays true).
      this.abiEncFromCd(t, cdPtr, ptr, forceValidate || !isValueLeafArray(t), out, false, !forceValidate);
      return ptr;
    }
    // a dynamic array T[]: alloc [len] + an len-word table; each element word holds either an inline
    // block (static element) or an ABSOLUTE pointer to a fresh element sub-image (dynamic element).
    if (t.kind === 'array' && t.length === undefined) {
      const len = this.fresh();
      out.push(`let ${len} := calldataload(${cdPtr})`);
      out.push(`if gt(${len}, 0xffffffffffffffff) { ${cap} }`);
      const elemRegion = this.fresh();
      out.push(`let ${elemRegion} := add(${cdPtr}, 0x20)`);
      if (isStaticType(t.element) && !isPointerHeadedStaticElem(t.element)) {
        // a STATIC VALUE element (Arr<u256,N>[]): inline blocks, exactly abiDecFromCd's static-element
        // layout (the image == the standard ABI image for a static value element). Decode inline.
        const es = abiHeadWords(t.element) * 32;
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(0x40)`);
        const nc = this.fresh();
        out.push(`let ${nc} := add(add(${ptr}, 0x20), mul(${len}, ${es}))`);
        out.push(`if or(gt(${nc}, 0xffffffffffffffff), lt(${nc}, ${ptr})) { ${cap} }`);
        out.push(`if gt(add(${elemRegion}, mul(${len}, ${es})), calldatasize()) { revert(0, 0) }`);
        out.push(`mstore(${ptr}, ${len})`);
        out.push(`mstore(0x40, ${nc})`);
        const dstHead = this.fresh();
        out.push(`let ${dstHead} := add(${ptr}, 0x20)`);
        const i = this.fresh();
        out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
        const inner: string[] = [];
        const ecd = this.fresh();
        inner.push(`let ${ecd} := add(${elemRegion}, mul(${i}, ${es}))`);
        const edst = this.fresh();
        inner.push(`let ${edst} := add(${dstHead}, mul(${i}, ${es}))`);
        // a STATIC VALUE element of a calldata->memory copy MASKS its value leaves (u256[][] inner
        // u256[], Arr<u256,N>[] inner Arr<u256,N>), matching solc's copy semantics; a static struct
        // element still validates (validate stays true).
        this.abiEncFromCd(t.element, ecd, edst, forceValidate || !isValueLeafArray(t), inner, false, !forceValidate);
        for (const l of inner) out.push('  ' + l);
        out.push('}');
        return ptr;
      }
      if (isPointerHeadedStaticElem(t.element)) {
        // a STATIC-STRUCT element (P[]). The SOURCE is INLINE ABI (element stride es = abiHeadWords(P)*32,
        // NO offset table), but the in-memory IMAGE is POINTER-HEADED: alloc [len] + a len-word ABSOLUTE-
        // pointer table, then per element decode the inline source block (the self-branch allocs+validates
        // an es-word element image and returns its pointer) and store that pointer. Allocation CAP BEFORE
        // the source data-bounds revert, matching the inline path's revert ordering byte-for-byte.
        const es = abiHeadWords(t.element) * 32;
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(0x40)`);
        const tableEnd = this.fresh();
        out.push(`let ${tableEnd} := add(add(${ptr}, 0x20), mul(${len}, 0x20))`);
        out.push(`if or(gt(${tableEnd}, 0xffffffffffffffff), lt(${tableEnd}, ${ptr})) { ${cap} }`);
        out.push(`if gt(add(${elemRegion}, mul(${len}, ${es})), calldatasize()) { revert(0, 0) }`);
        out.push(`mstore(${ptr}, ${len})`);
        out.push(`mstore(0x40, ${tableEnd})`); // claim the table; per-element images alloc PAST it
        const dstHead = this.fresh();
        out.push(`let ${dstHead} := add(${ptr}, 0x20)`);
        const i = this.fresh();
        out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
        const inner: string[] = [];
        const esrc = this.fresh();
        inner.push(`let ${esrc} := add(${elemRegion}, mul(${i}, ${es}))`);
        const ip = this.fresh();
        inner.push(`let ${ip} := ${this.abiDecFromCdToImage(t.element, esrc, inner, cap, forceValidate)}`);
        inner.push(`mstore(add(${dstHead}, mul(${i}, 0x20)), ${ip})`);
        for (const l of inner) out.push('  ' + l);
        out.push('}');
        return ptr;
      }
      // a DYNAMIC element (u256[] inner, bytes/string): [len] + an len-word ABSOLUTE-pointer table.
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      const tableEnd = this.fresh();
      out.push(`let ${tableEnd} := add(add(${ptr}, 0x20), mul(${len}, 0x20))`);
      out.push(`if or(gt(${tableEnd}, 0xffffffffffffffff), lt(${tableEnd}, ${ptr})) { ${cap} }`);
      out.push(`if gt(add(${elemRegion}, mul(${len}, 0x20)), calldatasize()) { revert(0, 0) }`);
      out.push(`mstore(${ptr}, ${len})`);
      out.push(`mstore(0x40, ${tableEnd})`); // claim the table; sub-images alloc PAST it
      const dstHead = this.fresh();
      out.push(`let ${dstHead} := add(${ptr}, 0x20)`);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
      const inner: string[] = [];
      const so = this.fresh();
      inner.push(`let ${so} := calldataload(add(${elemRegion}, mul(${i}, 0x20)))`);
      inner.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
      const se = this.fresh();
      inner.push(`let ${se} := add(${elemRegion}, ${so})`);
      inner.push(`if gt(add(${se}, ${cdElemHeadBytes(t.element)}), calldatasize()) { revert(0, 0) }`);
      const ip = this.fresh();
      inner.push(`let ${ip} := ${this.abiDecFromCdToImage(t.element, se, inner, cap, true)}`);
      inner.push(`mstore(add(${dstHead}, mul(${i}, 0x20)), ${ip})`);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
      return ptr;
    }
    // a FIXED array (Arr<P,N>) of a POINTER-HEADED STATIC element (static struct, or a nested static-struct
    // array). The SOURCE is N inline es-word blocks (NO offset table, NO length); the IMAGE is N absolute-
    // pointer words. Claim the N-word table first (sub-images alloc PAST it); source data-bounds check up
    // front (truncated -> empty revert), mirroring the dynamic-outer pointer branch's ordering.
    if (t.kind === 'array' && t.length !== undefined && isPointerHeadedStaticElem(t.element)) {
      const es = abiHeadWords(t.element) * 32;
      out.push(`if gt(add(${cdPtr}, ${t.length * es}), calldatasize()) { revert(0, 0) }`);
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      out.push(`mstore(0x40, add(${ptr}, ${t.length * 32}))`); // claim the table; sub-images alloc PAST it
      for (let k = 0; k < t.length; k++) {
        const esrc = k === 0 ? cdPtr : `add(${cdPtr}, ${k * es})`;
        const ip = this.fresh();
        out.push(`let ${ip} := ${this.abiDecFromCdToImage(t.element, esrc, out, cap, forceValidate)}`);
        out.push(`mstore(add(${ptr}, ${k * 32}), ${ip})`);
      }
      return ptr;
    }
    // a FIXED array of a DYNAMIC element (Arr<u256[],N>): N absolute-pointer words, no length header.
    if (t.kind === 'array' && t.length !== undefined) {
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      out.push(`mstore(0x40, add(${ptr}, ${t.length * 32}))`); // claim the table; sub-images alloc PAST it
      for (let k = 0; k < t.length; k++) {
        const so = this.fresh();
        out.push(`let ${so} := calldataload(add(${cdPtr}, ${k * 32}))`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${cdPtr}, ${so})`);
        out.push(`if gt(add(${se}, ${cdElemHeadBytes(t.element)}), calldatasize()) { revert(0, 0) }`);
        const ip = this.fresh();
        out.push(`let ${ip} := ${this.abiDecFromCdToImage(t.element, se, out, cap, true)}`);
        out.push(`mstore(add(${ptr}, ${k * 32}), ${ip})`);
      }
      return ptr;
    }
    // LIFT #5: a DYNAMIC-field struct element (a D[] element where D has a bytes/string/dynamic-array
    // field) from a RAW calldata base. Decode the tuple at `cdPtr` into the SAME pointer-headed image a
    // memDynStruct local / a B3 P[]-of-dyn-struct element uses (value/static-aggregate fields inline;
    // each dynamic field's head word = an ABSOLUTE pointer to its own fresh [len][..] sub-image). The
    // calldata twin of buildDynStructFromMemBlob; uses calldatasize() as the source data-bounds limit
    // and the caller-selected `cap` for oversized-length / alloc-overflow (panic(0x41) in the cd->mem
    // copy context, matching solc's calldata->memory deep copy). Restricted to the isDynStructLeaf field
    // set the rest of the dyn-struct machinery admits (a nested-struct / struct-element-array field stays
    // gated upstream, so it never reaches here).
    if (t.kind === 'struct' && isDynamicType(t)) {
      return this.buildDynStructFromCdBase(t, cdPtr, out, cap);
    }
    // any other shape (a calldata struct over an arbitrary offset whose field set is unsupported, etc.):
    // SAFE clean reject (a clean reject beats a miscompile).
    throw new UnsupportedError(`abiDecFromCdToImage: unsupported type '${t.kind}'`);
  }

  /** The STORAGE twin of abiDecFromMemToImage / abiDecFromCdToImage: deep-copy a STORAGE reference at
   *  `slot` into a fresh pointer-headed memory IMAGE and return its absolute pointer (`let row: bytes[] =
   *  this.blobs`). Mirrors the calldata/mem twins, but reads canonical storage (no malformed-input bounds
   *  or Panic(0x41): solc's storage->memory deep copy never reverts on size, the stored length is trusted),
   *  so it is the structural mirror without the source-bounds guards. The CRUX vs abiEncFromStorage: that
   *  function emits the ABI-encoded blob (RELATIVE offsets) for a reference-element array, which is NOT a
   *  memory image; here every dynamic / pointer-headed element word holds an ABSOLUTE pointer to a fresh
   *  sub-image, exactly the layout the memArray read/write/encode codec consumes. Value-element arrays and
   *  static elements are byte-invariant ([len][inline]), so this is identical to the abiEncFromStorage
   *  result there - but routing them here too keeps one path. */
  private abiDecFromStorageToImage(t: JethType, slot: string, ctx: LowerCtx, out: string[]): string {
    // a bytes/string leaf: alloc a [len][data] blob, return its absolute pointer (copyStrToMem allocs at
    // the free pointer and bumps it).
    if (isBytesLike(t)) {
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      const sz = this.fresh();
      out.push(`let ${sz} := ${this.copyStrToMem()}(${slot}, ${ptr})`);
      out.push(`mstore(0x40, add(${ptr}, ${sz}))`);
      return ptr;
    }
    // a STATIC element (value / static struct / static VALUE fixed array): its image is abiHeadWords(t)
    // inline words, copied leaf-by-leaf from storage. A static-STRUCT-leaf fixed array (Arr<P,N>) is
    // STATIC but POINTER-HEADED, so it is excluded here and handled by the FIXED-outer branch below.
    if (isStaticType(t) && !isStaticStructFixedLeafArray(t)) {
      const hw = abiHeadWords(t);
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      out.push(`mstore(0x40, add(${ptr}, ${hw * 32}))`);
      this.abiEncFromStorage(t, slot, 0, ptr, out); // static leaves are inline-identical in image and ABI
      return ptr;
    }
    // a dynamic array T[]: alloc [len] + an len-word table; each element word holds either an inline block
    // (static value element) or an ABSOLUTE pointer to a fresh element sub-image (pointer-headed / dynamic).
    if (t.kind === 'array' && t.length === undefined) {
      const len = this.fresh();
      out.push(`let ${len} := sload(${slot})`);
      const dataSlot = this.fresh();
      out.push(`let ${dataSlot} := ${this.arrayDataSlotHelper()}(${slot})`);
      const elem = t.element;
      if (isStaticType(elem) && !isPointerHeadedStaticElem(elem)) {
        // a STATIC VALUE element (u256[] or Arr<u256,N>[]): inline blocks ([len][e0..]), byte-identical to
        // the value-element memArray image. Reuse abiEncFromStorage (image == ABI for static value elems).
        const dst = this.fresh();
        out.push(`let ${dst} := mload(0x40)`);
        const size = this.abiEncFromStorage(t, slot, 0, dst, out);
        out.push(`mstore(0x40, add(${dst}, ${size}))`);
        return dst;
      }
      const sc = storageSlotCount(elem);
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      out.push(`mstore(0x40, add(add(${ptr}, 0x20), mul(${len}, 0x20)))`); // [len] + ptr table; sub-images alloc PAST
      out.push(`mstore(${ptr}, ${len})`);
      const dstHead = this.fresh();
      out.push(`let ${dstHead} := add(${ptr}, 0x20)`);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
      const inner: string[] = [];
      const eb = this.fresh();
      inner.push(`let ${eb} := add(${dataSlot}, mul(${i}, ${sc}))`);
      const ip = this.fresh();
      inner.push(`let ${ip} := ${this.abiDecFromStorageToImage(elem, eb, ctx, inner)}`);
      inner.push(`mstore(add(${dstHead}, mul(${i}, 0x20)), ${ip})`);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
      return ptr;
    }
    // a FIXED array (Arr<P,N> / Arr<u256[],N>): N absolute-pointer words, no length header. Each element is
    // sc storage slots apart; per element build a fresh sub-image and store its pointer.
    if (t.kind === 'array' && t.length !== undefined) {
      const elem = t.element;
      const sc = storageSlotCount(elem);
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      out.push(`mstore(0x40, add(${ptr}, ${t.length * 32}))`); // claim the table; sub-images alloc PAST it
      for (let k = 0; k < t.length; k++) {
        const eb = k === 0 ? slot : `add(${slot}, ${k * sc})`;
        const ip = this.fresh();
        out.push(`let ${ip} := ${this.abiDecFromStorageToImage(elem, eb, ctx, out)}`);
        out.push(`mstore(add(${ptr}, ${k * 32}), ${ip})`);
      }
      return ptr;
    }
    // a DYNAMIC-field struct element (P with bytes/string/dyn fields): build its pointer-headed image via
    // the existing storage dyn-struct copier (value fields inline, dynamic fields a fresh-blob pointer).
    if (t.kind === 'struct' && isDynamicType(t)) {
      return this.buildDynStructFromStorage(t, slot, ctx, out);
    }
    throw new UnsupportedError(`abiDecFromStorageToImage: unsupported type '${t.kind}'`);
  }

  /** LIFT #5: decode a DYNAMIC-field struct from a RAW calldata tuple base `cdBase` into the POINTER-
   *  HEADED image a memDynStruct local / a B3 P[]-of-dyn-struct element consumes (value & nested-static-
   *  aggregate fields inline; a bytes/string / dynamic-array / nested-dynamic-leaf-array field's head word
   *  holds an ABSOLUTE pointer to a fresh sub-image). The calldata twin of buildDynStructFromMemBlob:
   *  reads via calldataload, bounds every field tail against calldatasize(), and reuses abiDecFromCdToImage
   *  for each tail (so the short-args / OOB / oversized-length revert semantics are byte-identical to solc's
   *  calldata tuple-member decode). `cap` selects the oversized-length / alloc-overflow behavior (revert(0,0)
   *  for an abi.decode-style member, panic(0x41) for a calldata->memory deep copy). The field shape is
   *  restricted to isDynStructLeaf (validated upstream by the analyzer gates), the same set
   *  buildDynStructFromMemBlob / buildDynStructFromCalldata admit. */
  private buildDynStructFromCdBase(
    struct: JethType & { kind: 'struct' },
    cdBase: string,
    out: string[],
    cap: string,
  ): string {
    const headWords = tupleHeadWords(struct);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(0x40, add(${ptr}, ${headWords * 32}))`); // claim the head; sub-images alloc PAST it
    let hw = 0;
    for (const f of struct.fields) {
      const at = hw === 0 ? ptr : `add(${ptr}, ${hw * 32})`;
      const headAt = hw === 0 ? cdBase : `add(${cdBase}, ${hw * 32})`;
      if (isDynamicType(f.type)) {
        // a dynamic field (bytes/string, a dynamic value-array, or a nested-dynamic-leaf array): the head
        // word is an OFFSET relative to the tuple start. Resolve + bound the tail, then decode it into a
        // fresh sub-image via the self-recursion and store ITS absolute pointer in the head word.
        const so = this.fresh();
        out.push(`let ${so} := calldataload(${headAt})`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${cdBase}, ${so})`);
        out.push(`if gt(add(${se}, ${cdElemHeadBytes(f.type)}), calldatasize()) { revert(0, 0) }`);
        const ip = this.fresh();
        out.push(`let ${ip} := ${this.abiDecFromCdToImage(f.type, se, out, cap)}`);
        out.push(`mstore(${at}, ${ip})`);
        hw += 1;
      } else {
        // a static field (value / nested static struct / static fixed array): its abiHeadWords(type) leaf
        // words are inline at the tuple head; copy + validate each leaf word (the cd-source leaf copy is
        // exactly encodeStaticInline's calldata branch, inlined here to stay ctx-free).
        for (const leaf of abiLeaves(f.type)) {
          const disp = leaf.wordOffset * 32;
          const src = disp === 0 ? headAt : `add(${headAt}, ${disp})`;
          const w = this.fresh();
          out.push(`let ${w} := calldataload(${src})`);
          const guard = this.validateInput(leaf.type, w);
          if (guard) out.push(guard);
          out.push(`mstore(${disp === 0 ? at : `add(${at}, ${disp})`}, ${w})`);
        }
        hw += abiHeadWords(f.type);
      }
    }
    return ptr;
  }

  /** Decode the bytes value `data` into N components of `types` (abi.decode). Materializes the source
   *  to a memory [len][data] image, then for each top-level component reads its head word at
   *  blobData+32*i: a STATIC component is decoded inline at that head position; a DYNAMIC component
   *  reads the head as an offset (relative to blobData), bounds it, and decodes the tail into a fresh
   *  memory image. Returns one Yul register per component (a value word, or a memory image pointer for
   *  a reference component). The component layout (one head word per top-level type, regardless of how
   *  many leaf words a static aggregate occupies in a NESTED position) matches solc's outer tuple. */
  private lowerAbiDecode(data: Expr, types: JethType[], ctx: LowerCtx, out: string[]): string[] {
    const { mp } = this.toMemory(this.lowerDynamic(data, ctx, out), out);
    const blobData = this.fresh();
    out.push(`let ${blobData} := add(${mp}, 0x20)`);
    const blobEnd = this.fresh();
    out.push(`let ${blobEnd} := add(${blobData}, mload(${mp}))`);
    // the outer head is one OFFSET word per DYNAMIC component plus abiHeadWords(t) inline words per
    // STATIC component (a static aggregate occupies all its leaf words inline in the outer tuple head,
    // exactly as solc lays it out); bound the whole head span against the blob.
    const headWords = (t: JethType): number => (isDynamicType(t) ? 1 : abiHeadWords(t));
    const totalHead = types.reduce((n, t) => n + headWords(t), 0);
    out.push(`if gt(add(${blobData}, ${totalHead * 32}), ${blobEnd}) { revert(0, 0) }`);
    const regs: string[] = [];
    let hw = 0;
    types.forEach((t) => {
      const head = `add(${blobData}, ${hw * 32})`;
      hw += headWords(t);
      if (!isDynamicType(t)) {
        // a static component is decoded INLINE at its head position. A value type yields one word
        // (returned directly); a static aggregate is materialized into a fresh memory image.
        if (isStaticValueType(t)) {
          const w = this.fresh();
          out.push(`let ${w} := mload(${head})`);
          const g = this.validateInput(t, w);
          if (g) out.push(g);
          regs.push(w);
        } else if (t.kind === 'array' && isStaticStructFixedLeafArray(t)) {
          // Batch A: a STATIC fixed-outer static-struct array (Arr<P,N>) decodes into B's POINTER-HEADED
          // image (N absolute-pointer words -> fresh per-element images). abiDecFromMemToImage self-manages
          // 0x40 (the N-word table is claimed BEFORE the per-element images alloc), unlike abiDecFromMem
          // which would write the table into a pre-claimed `ptr` and then collide with sub-image allocs.
          regs.push(this.abiDecFromMemToImage(t, head, blobEnd, out));
        } else {
          const ptr = this.fresh();
          out.push(`let ${ptr} := mload(0x40)`);
          const sz = this.abiDecFromMem(t, head, ptr, blobEnd, out);
          out.push(`mstore(0x40, add(${ptr}, ${sz}))`);
          regs.push(ptr);
        }
      } else {
        // a dynamic component: the head word is an offset relative to blobData. Bound it, then decode
        // the tail into a fresh memory image (the register holds that image pointer).
        const so = this.fresh();
        out.push(`let ${so} := mload(${head})`);
        out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
        const se = this.fresh();
        out.push(`let ${se} := add(${blobData}, ${so})`);
        out.push(`if gt(add(${se}, ${cdElemHeadBytes(t)}), ${blobEnd}) { revert(0, 0) }`);
        if (t.kind === 'struct') {
          // a dynamic-field struct: build the POINTER-HEADED image a JETH struct local consumes (NOT the
          // standard ABI image abiDecFromMem produces); buildDynStructFromMemBlob manages its own alloc.
          regs.push(this.buildDynStructFromMemBlob(t, se, blobEnd, out));
        } else if (
          t.kind === 'array' &&
          (isDynamicType(t.element) ||
            // Cat B: a DYNAMIC-outer STATIC-STRUCT-element array (P[]) is pointer-headed too.
            (t.length === undefined && t.element.kind === 'struct') ||
            // Batch A: a DYNAMIC-outer FIXED-STRUCT-ARRAY-element array (Arr<P,N>[]) is pointer-headed too.
            isStaticStructAnyLeafArray(t))
        ) {
          // Residual C1/C3: an array with a DYNAMIC element (u256[][], Arr<u256[],N>, bytes[], string[]).
          // Cat B / Batch A: a STATIC-STRUCT element array (P[]) or a FIXED-STRUCT-ARRAY element array
          // (Arr<P,N>[]) is ALSO pointer-headed now (each element is an absolute pointer to a fresh
          // per-element image). abiDecFromMem would write the STANDARD ABI image (relative offsets / inline
          // blocks), but Residual B's memory-array readers expect ABSOLUTE pointers. Decode into B's
          // pointer-headed image, which abiDecFromMemToImage allocates and returns (SAME blob bounds checks).
          regs.push(this.abiDecFromMemToImage(t, se, blobEnd, out));
        } else {
          // a value-element array (u256[]) or a static fixed VALUE-array-element array (Arr<u256,N>[]):
          // abiDecFromMem's standard image already matches B's representation ([len][elems] / [len][inline
          // blocks], no pointers).
          const ptr = this.fresh();
          out.push(`let ${ptr} := mload(0x40)`);
          const sz = this.abiDecFromMem(t, se, ptr, blobEnd, out);
          out.push(`mstore(0x40, add(${ptr}, ${sz}))`);
          regs.push(ptr);
        }
      }
    });
    return regs;
  }

  /** Echo a whole STORAGE state variable of dynamic type `t` (base storage slot
   *  `slot`) into a fresh ABI return blob [0x20][value encoding]. The storage-source
   *  twin of echoParam; UNBOUNDED nesting via abiEncFromStorage recursion. */
  private echoStorage(slot: bigint, t: JethType, out: string[]): { ptr: string; size: string } {
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`);
    const size = this.abiEncFromStorage(t, String(slot), 0, `add(${ptr}, 0x20)`, out);
    out.push(`mstore(0x40, add(add(${ptr}, 0x20), ${size}))`);
    return { ptr, size: `add(0x20, ${size})` };
  }

  /** Echo a whole DYNAMIC-ARRAY field of a calldata dyn-struct (array) element as a VALUE:
   *  `xs[i].grid` (grid: u256[][]) / `xs[i].items` (items: D[]). The field's head slot holds an
   *  OFFSET (relative to the containing tuple base) to the array's `[len][...]` header. Resolve
   *  that header, then re-encode the WHOLE array via the recursive calldata codec abiEncFromCd
   *  (which reads `[len]` itself and lays out the offset table + tails for any element shape).
   *  The array is dynamic, so the return blob is `[0x20][encoding]`. A value-leaf array (u256[][])
   *  MASKS dirty leaves; a struct- / bytes-leaf array VALIDATES (the struct/bytes branches force
   *  field validation). cap = empty-revert, matching solc's calldata->memory copy of a malformed
   *  inner length/offset (truncated/OOB -> empty revert, oversized inner len -> Panic 0x41 inside
   *  the bytes/struct leaf decode is itself capped to empty-revert here). */
  /** Resolve the calldata HEADER pointer (the [len] word, or the N-word table for a fixed array) of a
   *  whole DYNAMIC-ARRAY field of a calldata dyn-struct (array) element: the field's head holds an
   *  offset (relative to the containing tuple base) to the array header. Unsigned 2^64 cap + length-word
   *  readability check; deep payload bounds are the codec's responsibility. */
  private cdFieldArrayHeader(place: CdDynPlace, ctx: LowerCtx, out: string[]): string {
    const base = this.lowerCdDynBase(place, ctx, out);
    const last = place.steps[place.steps.length - 1]!;
    const offPtr = last.headWords === 0 ? base : `add(${base}, ${last.headWords * 32})`;
    const off = this.fresh();
    out.push(`let ${off} := calldataload(${offPtr})`);
    out.push(`if gt(${off}, 0xffffffffffffffff) { revert(0, 0) }`);
    const hdr = this.fresh();
    out.push(`let ${hdr} := add(${base}, ${off})`);
    out.push(`if iszero(slt(add(${hdr}, 0x1f), calldatasize())) { revert(0, 0) }`);
    return hdr;
  }

  private echoCdFieldArray(place: CdDynPlace, t: JethType, ctx: LowerCtx, out: string[]): { ptr: string; size: string } {
    const hdr = this.cdFieldArrayHeader(place, ctx, out);
    const validate = !isValueLeafArray(t);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`);
    // RETURN of a whole field array = a full calldata->memory DECODE/copy: an oversized inner length /
    // alloc overflow Panics 0x41 (capEmptyRevert=false), matching solc (empirically verified vs 0.8.35:
    // grid/items oversized inner len -> Panic 0x41). Truncated / OOB source still EMPTY-reverts (those
    // checks are unconditional). NOTE: this differs from `return xs[i]` (the array-of-array ELEMENT
    // lazy-access slice, which empty-reverts on oversized) - a struct FIELD is a whole decode, not a slice.
    const size = this.abiEncFromCd(t, hdr, `add(${ptr}, 0x20)`, validate, out, false);
    out.push(`mstore(0x40, add(add(${ptr}, 0x20), ${size}))`);
    return { ptr, size: `add(0x20, ${size})` };
  }

  /** Echo a whole INNER array reached by DESCENDING a nested-dynamic-array field of a calldata
   *  dyn-struct (array) element as a VALUE: `xs[i].grid[j]` (grid: u256[][] -> inner u256[]). Mirror
   *  lowerArrayRef's cdDynFieldNested descent EXACTLY (resolve the field's offset table, then descend
   *  one offset-table level per index with a Panic(0x32) bound), but stop at the inner array's HEADER
   *  (the [len] word = dataOff - 0x20 for a dynamic inner level), then re-encode the whole array via
   *  abiEncFromCd. The return blob is [0x20][encoding]; a value-leaf inner array MASKS, an aggregate
   *  inner array VALIDATES. cap = empty-revert (solc's calldata->memory copy semantics). */
  /** Resolve the calldata HEADER pointer of a whole INNER array reached by DESCENDING a nested-dynamic-
   *  array field (`xs[i].grid[j]`): decode the field's offset table, then descend one offset-table level
   *  per index (Panic(0x32) bound on each), stopping at the inner array's header (the [len] word for a
   *  dynamic inner level; the N-word table for a fixed inner level). Mirrors lowerArrayRef's
   *  cdDynFieldNested descent exactly. */
  private cdNestedFieldArrayHeader(place: CdDynPlace, indices: Expr[], ctx: LowerCtx, out: string[]): string {
    const cbase = this.lowerCdDynBase(place, ctx, out);
    const last = place.steps[place.steps.length - 1]!;
    const offPtr = last.headWords === 0 ? cbase : `add(${cbase}, ${last.headWords * 32})`;
    const tableStart = this.fresh();
    const outerLen = this.fresh();
    out.push(`let ${tableStart}, ${outerLen} := ${this.calldataArrayAt()}(${cbase}, ${offPtr}, 0x20)`);
    const fieldArr = last.fieldType as JethType & { kind: 'array' };
    let base = tableStart;
    let count: string = outerLen;
    let elemT: JethType = fieldArr.element;
    let header = ''; // the [len] word of the resolved inner array (set on the final descent)
    indices.forEach((idxExpr) => {
      const i = this.fresh();
      out.push(`let ${i} := ${this.lowerExpr(idxExpr, ctx, out)}`);
      out.push(`if iszero(lt(${i}, ${count})) { ${this.panic()}(0x32) }`);
      if (elemT.kind === 'array' && elemT.length === undefined) {
        const stride = isDynamicType(elemT.element) ? 32 : abiHeadWords(elemT.element) * 32;
        const nb = this.fresh();
        const nl = this.fresh();
        out.push(`let ${nb}, ${nl} := ${this.calldataInnerArray()}(${base}, ${i}, ${stride})`);
        // nb = data start (after [len]); the inner array HEADER (length word) is nb - 0x20.
        header = `sub(${nb}, 0x20)`;
        base = nb;
        count = nl;
      } else if (elemT.kind === 'array' && elemT.length !== undefined) {
        const nb = this.fresh();
        out.push(`let ${nb} := ${this.calldataNestedOff()}(${base}, ${i})`);
        // a FIXED inner level has NO length word: the resolved offset IS the header (the N-word table).
        header = nb;
        base = nb;
        count = String(elemT.length);
      } else {
        throw new UnsupportedError(`cannot index calldata dyn-struct nested field element of kind '${elemT.kind}'`);
      }
      elemT = (elemT as JethType & { kind: 'array' }).element;
    });
    return header;
  }

  private echoCdNestedFieldArray(
    place: CdDynPlace,
    indices: Expr[],
    t: JethType,
    ctx: LowerCtx,
    out: string[],
  ): { ptr: string; size: string } {
    const header = this.cdNestedFieldArrayHeader(place, indices, ctx, out);
    const validate = !isValueLeafArray(t);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    // RETURN = a full calldata->memory decode: oversized inner length -> Panic 0x41 (capEmptyRevert=false),
    // truncated/OOB -> empty revert (unconditional). Same whole-decode semantics as echoCdFieldArray.
    if (isDynamicType(t)) {
      out.push(`mstore(${ptr}, 0x20)`);
      const size = this.abiEncFromCd(t, header, `add(${ptr}, 0x20)`, validate, out, false);
      out.push(`mstore(0x40, add(add(${ptr}, 0x20), ${size}))`);
      return { ptr, size: `add(0x20, ${size})` };
    }
    const size = this.abiEncFromCd(t, header, ptr, validate, out, false);
    out.push(`mstore(0x40, add(${ptr}, ${size}))`);
    return { ptr, size };
  }

  /** Echo a whole nested-STRUCT field of a dynamic-struct calldata param (return o.inner)
   *  into a fresh ABI return blob [0x20][tuple encoding]. Resolve the inner struct's tuple
   *  start via the navigator: lowerCdDynBase folds every step but the last to the containing
   *  tuple base; the last step's field is then resolved - a DYNAMIC nested struct reads its
   *  offset word (base resets to base+offset, calldataTupleAt) while a STATIC one is inline
   *  at the field offset. The whole inner struct is re-encoded from that tuple base by the
   *  same recursive calldata->memory codec (abiEncFromCd) the whole-param echo uses. */
  /** Resolve the CALLDATA tuple-start of a whole nested dynamic-struct FIELD `place` (o.inner):
   *  descend the parent tuple to the final step's field offset, then - because the field's value is
   *  itself a dynamic struct - follow its offset word to the sub-tuple base (crossDynamic), validating
   *  the sub-tuple's whole head is in range. Shared by the `return o.inner` echo (echoCdDynField) and
   *  the calldata-field -> memory copy / re-encode path (buildDynStructFromCalldata), so both read the
   *  SAME field tuple-start instead of the parent's (the V2 miscompile spliced in the sibling field). */
  private cdDynStructFieldTupleStart(
    place: CdDynPlace,
    struct: JethType & { kind: 'struct' },
    ctx: LowerCtx,
    out: string[],
  ): string {
    const base = this.lowerCdDynBase(place, ctx, out);
    const last = place.steps[place.steps.length - 1]!;
    const fieldOff = last.headWords === 0 ? base : `add(${base}, ${last.headWords * 32})`;
    if (last.crossDynamic) {
      const nb = this.fresh();
      out.push(`let ${nb} := ${this.calldataTupleAt()}(${base}, ${fieldOff}, ${tupleHeadWords(struct) * 32})`);
      return nb;
    }
    return fieldOff;
  }

  private echoCdDynField(place: CdDynPlace, t: JethType, ctx: LowerCtx, out: string[]): { ptr: string; size: string } {
    const struct = t as JethType & { kind: 'struct' };
    const tupleStart = this.cdDynStructFieldTupleStart(place, struct, ctx, out);
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    if (isDynamicType(t)) {
      out.push(`mstore(${ptr}, 0x20)`);
      const size = this.abiEncFromCd(t, tupleStart, `add(${ptr}, 0x20)`, true, out);
      out.push(`mstore(0x40, add(add(${ptr}, 0x20), ${size}))`);
      return { ptr, size: `add(0x20, ${size})` };
    }
    const size = this.abiEncFromCd(t, tupleStart, ptr, true, out);
    out.push(`mstore(0x40, add(${ptr}, ${size}))`);
    return { ptr, size };
  }

  /** ABI-encode a value of type `t` read from a RUNTIME storage `slotExpr` as a full
   *  return blob: a dynamic value gets the `[0x20][encoding]` wrapper, a static
   *  value/struct/fixed-array is written flat. Used for `return this.m[k]` (whole
   *  mapping value), where the slot is the runtime keccak(key . base). */
  private returnStorageValue(slotExpr: string, t: JethType, out: string[]): { ptr: string; size: string } {
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    const total = this.fresh();
    if (isDynamicType(t)) {
      out.push(`mstore(${ptr}, 0x20)`);
      const size = this.abiEncFromStorage(t, slotExpr, 0, `add(${ptr}, 0x20)`, out);
      out.push(`let ${total} := add(0x20, ${size})`);
    } else {
      const size = this.abiEncFromStorage(t, slotExpr, 0, ptr, out);
      out.push(`let ${total} := ${size}`);
    }
    out.push(`mstore(0x40, add(${ptr}, ${total}))`);
    return { ptr, size: total };
  }

  /** `return ps[i]` (whole struct element of a calldata struct array): bounds-check i
   *  (Panic 0x32), resolve the element's calldata head (contiguous for a STATIC struct;
   *  offset-located via the per-element table for a DYNAMIC struct, with solc's unsigned
   *  2^64 cap + readability check), then re-encode it into a fresh ABI return blob via the
   *  recursive calldata codec (a static struct flat; a dynamic struct with the [0x20]
   *  wrapper). The calldata twin of returnStorageValue/structArrayElem. */
  /** Compute the CALLDATA tuple-start base of element `index` of a calldata struct array,
   *  bounds-checked exactly like ps[i].field (Panic 0x32 on OOB; a dynamic element also bounds
   *  its offset word + head against calldatasize). A STATIC element is contiguous (dataStart +
   *  i*stride); a DYNAMIC element is offset-located (dataStart + offset[i]). Shared by the
   *  `return ps[i]` echo and the memory-struct-local materialization (let p: P = ps[i]). */
  private cdArrayElemBase(arr: ArrayExpr, index: Expr, t: JethType, ctx: LowerCtx, out: string[]): string {
    const ref = this.lowerArrayRef(arr, ctx, out);
    if (ref.src !== 'calldata') throw new UnsupportedError('cdArrayElemBase requires a calldata array');
    const i = this.fresh();
    out.push(`let ${i} := ${this.lowerExpr(index, ctx, out)}`);
    out.push(`if iszero(lt(${i}, ${ref.length})) { ${this.panic()}(0x32) }`);
    const eb = this.fresh();
    if (isStaticType(t)) {
      // contiguous static elements: base = dataStart + i*stride (the whole payload was
      // already validated readable when the array was bound).
      const stride = abiHeadWords(t) * 32;
      out.push(`let ${eb} := add(${ref.offset}, mul(${i}, ${stride}))`);
      return eb;
    }
    // dynamic element: ref.offset is the per-element offset-table base (= data start). Element
    // i's data is at base + offset[i]; mirror abiEncFromCd's dynamic-array element resolution.
    const so = this.fresh();
    out.push(`let ${so} := calldataload(add(${ref.offset}, mul(${i}, 0x20)))`);
    out.push(`if gt(${so}, 0xffffffffffffffff) { revert(0, 0) }`);
    out.push(`let ${eb} := add(${ref.offset}, ${so})`);
    out.push(`if gt(add(${eb}, ${cdElemHeadBytes(t)}), calldatasize()) { revert(0, 0) }`);
    return eb;
  }

  private returnCdArrayElem(
    arr: ArrayExpr,
    index: Expr,
    t: JethType,
    ctx: LowerCtx,
    out: string[],
    capEmptyRevert = false,
  ): { ptr: string; size: string } {
    const eb = this.cdArrayElemBase(arr, index, t, ctx, out);
    // A whole sub-aggregate ELEMENT whose ultimate leaf is a pure VALUE type (u8[][] -> u8[],
    // bool[][] -> bool[], Arr<u8,N>[] -> Arr<u8,N>, and any deeper value-leaf nesting) is a
    // calldata->memory COPY: solc MASKS dirty leaves (and 1ifies a non-0/1 bool) rather than
    // reverting, exactly like a plain top-level value-array return (uint8[]). validateInput would
    // EMPTY-revert on dirty bits (a fail-safe over-validation). A struct- / bytes/string-leaf element
    // still VALIDATES (the struct/bytes branches of abiEncFromCd force field validation regardless).
    const validate = !isValueLeafArray(t);
    if (isStaticType(t)) {
      const ptr = this.fresh();
      out.push(`let ${ptr} := mload(0x40)`);
      const size = this.abiEncFromCd(t, eb, ptr, validate, out, capEmptyRevert);
      out.push(`mstore(0x40, add(${ptr}, ${size}))`);
      return { ptr, size };
    }
    const ptr = this.fresh();
    out.push(`let ${ptr} := mload(0x40)`);
    out.push(`mstore(${ptr}, 0x20)`);
    const size = this.abiEncFromCd(t, eb, `add(${ptr}, 0x20)`, validate, out, capEmptyRevert);
    const total = this.fresh();
    out.push(`let ${total} := add(0x20, ${size})`);
    out.push(`mstore(0x40, add(${ptr}, ${total}))`);
    return { ptr, size: total };
  }

  /** Recursively encode a value of type `t` read from STORAGE (base slot `slot`, byte
   *  `offset` within the slot for a packed value) into a fresh ABI blob at memory
   *  `dst`. Returns a Yul size expr. Compile-time recursion over `t` => unbounded
   *  nesting; runtime loops for array lengths. The storage-source twin of abiEncFromCd
   *  (storage values are already canonical, so no dirty-bit validation is needed). */
  private abiEncFromStorage(t: JethType, slot: string, offset: number, dst: string, out: string[]): string {
    if (isStaticValueType(t)) {
      out.push(`mstore(${dst}, ${this.loadState(t, slot, offset)})`);
      return '32';
    }
    if (isStaticType(t)) {
      // static struct / fixed array of static: copy each leaf from its storage slot.
      for (const leaf of structStorageLeaves(t)) {
        const ls = leaf.storageSlot === 0 ? slot : `add(${slot}, ${leaf.storageSlot})`;
        out.push(`mstore(add(${dst}, ${leaf.abiWord * 32}), ${this.loadState(leaf.type, ls, leaf.storageOffset)})`);
      }
      return String(abiHeadWords(t) * 32);
    }
    if (isBytesLike(t)) {
      // copy the storage bytes/string DIRECTLY to dst (no temp allocation, which
      // would clobber the output blob being built at the free pointer).
      const sz = this.fresh();
      out.push(`let ${sz} := ${this.copyStrToMem()}(${slot}, ${dst})`);
      return sz;
    }
    if (t.kind === 'array' && t.length === undefined) {
      const len = this.fresh();
      out.push(`let ${len} := sload(${slot})`);
      out.push(`mstore(${dst}, ${len})`);
      const dataSlot = this.fresh();
      out.push(`let ${dataSlot} := ${this.arrayDataSlotHelper()}(${slot})`);
      const dstHead = this.fresh();
      out.push(`let ${dstHead} := add(${dst}, 0x20)`);
      const elem = t.element;
      if (isStaticType(elem)) {
        const es = abiHeadWords(elem) * 32;
        const i = this.fresh();
        out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
        const inner: string[] = [];
        if (isStaticValueType(elem)) {
          inner.push(`mstore(add(${dstHead}, mul(${i}, ${es})), ${this.arrayElemLoad(elem, dataSlot, i)})`);
        } else {
          const eb = this.fresh();
          inner.push(`let ${eb} := add(${dataSlot}, mul(${i}, ${storageSlotCount(elem)}))`);
          for (const leaf of structStorageLeaves(elem)) {
            const ls = leaf.storageSlot === 0 ? eb : `add(${eb}, ${leaf.storageSlot})`;
            inner.push(
              `mstore(add(add(${dstHead}, mul(${i}, ${es})), ${leaf.abiWord * 32}), ${this.loadState(leaf.type, ls, leaf.storageOffset)})`,
            );
          }
        }
        for (const l of inner) out.push('  ' + l);
        out.push('}');
        return `add(0x20, mul(${len}, ${es}))`;
      }
      // dynamic elements (string[] / D[]): offset table + per-element tails.
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dstHead}, mul(${len}, 0x20))`);
      const sc = storageSlotCount(elem);
      const i = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${len}) { ${i} := add(${i}, 1) } {`);
      const inner: string[] = [];
      const eb = this.fresh();
      inner.push(`let ${eb} := add(${dataSlot}, mul(${i}, ${sc}))`);
      inner.push(`mstore(add(${dstHead}, mul(${i}, 0x20)), sub(${cursor}, ${dstHead}))`);
      const sz = this.abiEncFromStorage(elem, eb, 0, cursor, inner);
      inner.push(`${cursor} := add(${cursor}, ${sz})`);
      for (const l of inner) out.push('  ' + l);
      out.push('}');
      return `sub(${cursor}, ${dst})`;
    }
    if (t.kind === 'array' && t.length !== undefined) {
      // fixed array of a DYNAMIC element (Arr<string,N> / Arr<D,N>): an N-word offset
      // table (no length word) + per-element tails. Elements are contiguous in storage
      // (slotCount(elem) slots each); the static case is handled by isStaticType above.
      const n = t.length;
      const elem = t.element;
      const sc = storageSlotCount(elem);
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dst}, ${n * 32})`);
      for (let k = 0; k < n; k++) {
        const eb = k === 0 ? slot : `add(${slot}, ${k * sc})`;
        out.push(`mstore(add(${dst}, ${k * 32}), sub(${cursor}, ${dst}))`);
        const sz = this.abiEncFromStorage(elem, eb, 0, cursor, out);
        out.push(`${cursor} := add(${cursor}, ${sz})`);
      }
      return `sub(${cursor}, ${dst})`;
    }
    if (t.kind === 'struct') {
      // dynamic struct: static fields inline in the head, dynamic fields offset + tail.
      const headWords = tupleHeadWords(t);
      const cursor = this.fresh();
      out.push(`let ${cursor} := add(${dst}, ${headWords * 32})`);
      let hw = 0;
      for (const f of t.fields) {
        const fb = hw * 32;
        const fslot = f.slot === 0 ? slot : `add(${slot}, ${f.slot})`;
        if (!isDynamicType(f.type)) {
          this.abiEncFromStorage(f.type, fslot, f.offset, `add(${dst}, ${fb})`, out);
          hw += abiHeadWords(f.type);
        } else {
          out.push(`mstore(add(${dst}, ${fb}), sub(${cursor}, ${dst}))`);
          const sz = this.abiEncFromStorage(f.type, fslot, f.offset, cursor, out);
          out.push(`${cursor} := add(${cursor}, ${sz})`);
          hw += 1;
        }
      }
      return `sub(${cursor}, ${dst})`;
    }
    throw new UnsupportedError(`abiEncFromStorage: unsupported type '${t.kind}'`);
  }

  // ---- dynamic bytes/string values (Phase 4) -------------------------------

  /** Resolve a dynamic bytes/string expression to its source reference. */
  /** Build an abi.encode* bytes value in memory ([len][data]) and return its pointer. With a
   *  `selector` (encodeWithSelector) or `sig` (encodeWithSignature: bytes4(keccak256(sig))), a 4-byte
   *  selector is prepended to the standard encoding of the remaining args. */
  private buildAbiEncode(
    args: Expr[],
    packed: boolean,
    ctx: LowerCtx,
    out: string[],
    selector?: Expr,
    sig?: Expr,
  ): string {
    // W6A: abi.encode* flattens every argument into a fresh bytes blob at evaluation time - a
    // TRANSIENT capture context (solc reads the same words through its references at this instant;
    // internal-call args inside an argument re-force persistent).
    return this.inTransientCapture(() => this.buildAbiEncodeInner(args, packed, ctx, out, selector, sig));
  }

  private buildAbiEncodeInner(
    args: Expr[],
    packed: boolean,
    ctx: LowerCtx,
    out: string[],
    selector?: Expr,
    sig?: Expr,
  ): string {
    if (selector || sig) {
      let pfx: string;
      if (selector) {
        pfx = this.lowerExpr(selector, ctx, out); // bytes4, left-aligned (high 4 bytes)
      } else {
        const { mp, len } = this.toMemory(this.lowerDynamic(sig!, ctx, out), out);
        const h = this.fresh();
        out.push(`let ${h} := keccak256(add(${mp}, 0x20), ${len})`);
        // keccak256(sig)[0:4] = the high 4 bytes, left-aligned.
        pfx = `and(${h}, 0xffffffff00000000000000000000000000000000000000000000000000000000)`;
      }
      return this.buildAbiEncodeWithSelector(pfx, args, ctx, out);
    }
    return packed ? this.buildAbiEncodePacked(args, ctx, out) : this.buildAbiEncodeStd(args, ctx, out);
  }

  /** abi.encodeWithSelector/Signature: a 4-byte selector prefix (left-aligned in a register) followed
   *  by the standard abi.encode of the remaining args. The args' internal offsets stay relative to the
   *  start of the args encoding (after the selector), matching solc (selector ++ abi.encode(args)). */
  private buildAbiEncodeWithSelector(pfx: string, args: Expr[], ctx: LowerCtx, out: string[]): string {
    const argsBytes = this.buildAbiEncodeStd(args, ctx, out); // [len][data]
    const argsLen = this.fresh();
    out.push(`let ${argsLen} := mload(${argsBytes})`);
    const total = this.fresh();
    out.push(`let ${total} := add(4, ${argsLen})`);
    const ptr = this.fresh();
    out.push(`let ${ptr} := ${this.alloc()}(add(0x40, and(add(${total}, 0x1f), not(0x1f))))`);
    out.push(`mstore(${ptr}, ${total})`);
    const data = this.fresh();
    out.push(`let ${data} := add(${ptr}, 0x20)`);
    out.push(`mstore(${data}, ${pfx})`); // 4 selector bytes (high) + 28 zero
    out.push(`mcopy(add(${data}, 4), add(${argsBytes}, 0x20), ${argsLen})`);
    out.push(`mstore(add(${data}, ${total}), 0)`); // zero the trailing partial word
    return ptr;
  }

  /** Standard ABI encoding (head/tail, 32-byte aligned) as a bytes value. A value -> a padded word;
   *  a STATIC struct/fixed-array -> abiHeadWords leaf words INLINE (no offset); a bytes/string -> a
   *  head offset + [len][padded data] tail; a DYNAMIC value-array -> a head offset + [len][elems] tail.
   *  The head uses a cumulative word offset (a static aggregate spans multiple inline head words).
   *
   *  W7A TWO-PHASE: phase 1 evaluates every argument LEFT-TO-RIGHT to a value local or a reference
   *  handle (a live memory pointer / a frozen storage slot / a resolved calldata base) - all user
   *  side effects run here, in source order. After the capture-patch flush, phase 2 SERIALIZES each
   *  component in order, reading through the handles LATE (memory mutations by later siblings are
   *  visible; storage components read post-sibling storage; validation Panics fire at serialize
   *  time) - exactly solc's evaluation model (pinned by the W7A probe battery). */
  private buildAbiEncodeStd(args: Expr[], ctx: LowerCtx, out: string[]): string {
    const prevPatches = this.beginTwoPhase();
    const preps = args.map((a) => this.prepEncodeComponent(a, ctx, out));
    this.flushTwoPhase(prevPatches, out);
    const parts: EncPart[] = preps.map((finish) => finish(out));
    const headWords = parts.reduce((acc, p) => acc + ('inline' in p ? p.words : 1), 0);
    const headSize = 32 * headWords;
    const total = this.fresh();
    out.push(`let ${total} := ${headSize}`);
    for (const p of parts) {
      if ('len' in p) out.push(`${total} := add(${total}, add(0x20, and(add(${p.len}, 0x1f), not(0x1f))))`);
      else if ('size' in p) out.push(`${total} := add(${total}, ${p.size})`);
    }
    const ptr = this.fresh();
    out.push(`let ${ptr} := ${this.alloc()}(add(0x20, ${total}))`);
    out.push(`mstore(${ptr}, ${total})`);
    const data = this.fresh();
    out.push(`let ${data} := add(${ptr}, 0x20)`);
    const cursor = this.fresh();
    out.push(`let ${cursor} := add(${data}, ${headSize})`);
    let hw = 0;
    for (const p of parts) {
      const head = hw === 0 ? data : `add(${data}, ${32 * hw})`;
      if ('word' in p) {
        out.push(`mstore(${head}, ${p.word})`);
        hw += 1;
      } else if ('inline' in p) {
        out.push(`mcopy(${head}, ${p.mp}, ${p.words * 32})`);
        hw += p.words;
      } else if ('len' in p) {
        const pad = `and(add(${p.len}, 0x1f), not(0x1f))`;
        out.push(`mstore(${head}, sub(${cursor}, ${data}))`);
        out.push(`mstore(${cursor}, ${p.len})`);
        out.push(`mcopy(add(${cursor}, 0x20), add(${p.mp}, 0x20), ${pad})`);
        out.push(`${cursor} := add(${cursor}, add(0x20, ${pad}))`);
        hw += 1;
      } else {
        // dynamic value-array tail: [len][elems] blob, copied verbatim, offset in the head.
        out.push(`mstore(${head}, sub(${cursor}, ${data}))`);
        out.push(`mcopy(${cursor}, ${p.mp}, ${p.size})`);
        out.push(`${cursor} := add(${cursor}, ${p.size})`);
        hw += 1;
      }
    }
    return ptr;
  }

  /** W7A phase 1 of one ABI-encode component: evaluate the argument AT ITS SOURCE POSITION to a
   *  value local or a reference handle, and return the phase-2 finisher that SERIALIZES through the
   *  handle late. The branch taxonomy (and every codec it delegates to) mirrors the pre-two-phase
   *  buildAbiEncodeStd byte-for-byte; only the TIMING of the serializing reads/validations moves. */
  private prepEncodeComponent(a: Expr, ctx: LowerCtx, out: string[]): (o: string[]) => EncPart {
    const t = a.type;
    if (isBytesLike(t)) {
      // position: resolve the reference (index side effects, literal/ternary/encode materialization);
      // serialize: toMemory reads LATE (a memory ref is an alias; storage loadStr / calldatacopy run
      // at serialize time - solc reads a storage bytes component post-sibling).
      const ref = this.lowerDynamic(a, ctx, out);
      return (o) => this.toMemory(ref, o);
    }
    // Batch A: a POINTER-HEADED memory Arr<P,N> (a memAggregate local, an array literal / new Array, an
    // internal-call return, or a struct-array element m[i] of Arr<P,N>[]) is a STATIC type encoded INLINE,
    // but its MEMORY image is N pointer words - capture the image pointer at position, transcode to the
    // flat inline ABI body via abiEncFromMem at SERIALIZE time (late reads through the element pointers).
    // EXCLUDED: a static-aggregate FIELD (aggFieldRead, e.g. xs[i].pre) is ABI-FLATTENED INLINE in its
    // struct image, and a STORAGE / calldata source flattens via the branches below.
    //   abiDecode: an EXTERNAL self-/interface-call result (this.produce() / IFace(a).produce(), analyzed
    //   as abiDecode(extCall, T)) or a literal abi.decode(b, Arr<P,N>). lowerAbiDecode materializes the
    //   SAME pointer-headed image (Batch-A abiDecFromMemToImage) that the bind-first local holds, so it
    //   MUST ride this transcode branch too. Without it the abiDecode fell through to the plain static-
    //   aggregate branch below (aggToMemPtr), which returned the pointer-headed image as a supposedly-flat
    //   inline body - a MISCOMPILE that leaked the N leading absolute element pointers into the ABI head
    //   (abi.encode(this.produce()) / this.consume(this.produce())). The bind-first / direct-return /
    //   internal-call paths already MATCH and are untouched.
    const memFixedSrc =
      a.kind === 'arrayLit' ||
      a.kind === 'newArray' ||
      a.kind === 'memAggregate' ||
      a.kind === 'arrayGet' ||
      a.kind === 'call' ||
      a.kind === 'abiDecode' ||
      (a.kind === 'arrayValue' && (a.arr.base.kind === 'memArray' || a.arr.base.kind === 'memArrayExpr'));
    if (isStaticStructFixedLeafArray(t) && memFixedSrc) {
      const mp = this.aggArgToMemPtr(a, ctx, out);
      return (o) => ({ inline: true, mp: this.abiEncFromMemBlob(t, mp, ctx, o).mp, words: abiHeadWords(t) });
    }
    if (isStaticType(t) && (t.kind === 'struct' || t.kind === 'array')) {
      // a STORAGE source: freeze the slot at position (index side effects / bounds checks run now),
      // copy out of storage at SERIALIZE time (solc reads the slots post-sibling - W7A probes P2/P19).
      const slot = this.staticAggStorageSlot(a, ctx, out);
      if (slot !== undefined) {
        return (o) => ({ inline: true, mp: this.allocAggFromStorage(t, slot, o), words: abiHeadWords(t) });
      }
      // a whole STATIC calldata param: immutable data, no position effects; decode + VALIDATE at
      // serialize time (solc's validation Panics fire after sibling side effects - probe P11 model).
      if (a.kind === 'cdAggregateValue') {
        const param = a.param;
        return (o) => ({ inline: true, mp: this.allocAggFromCalldata(param, t, ctx, o), words: abiHeadWords(t) });
      }
      // a STATIC struct element of a calldata D[]: the element base resolves at position (index side
      // effects + Panic 0x32), the decode+validate copy runs at serialize time.
      if (a.kind === 'cdStructArrayElem') {
        const eb = this.cdArrayElemBase(a.arr, a.index, t, ctx, out);
        return (o) => {
          const ptr = this.fresh();
          o.push(`let ${ptr} := mload(0x40)`);
          const size = this.abiEncFromCd(t, eb, ptr, true, o, true);
          o.push(`mstore(0x40, add(${ptr}, ${size}))`);
          return { inline: true, mp: ptr, words: abiHeadWords(t) };
        };
      }
      // memory sources alias (memAggregate / arrayGet / aggFieldRead / call / ternary select);
      // a structNew/arrayLit freezes its flat image at position with capture PATCHES re-copying
      // any live ref args after phase 1; abi.decode decodes at position (it is an expression).
      // W6C: the fixed ENUM range check moves to SERIALIZE time (after the patch flush), solc's
      // validator_assert position in the two-phase model (probe P11: a reverting later sibling
      // wins over the Panic; P11b: state-writing siblings roll back identically).
      const mp = this.aggToMemPtr(a, ctx, out);
      return (o) => {
        this.validateEnumMemArray(t, mp, o);
        return { inline: true, mp, words: abiHeadWords(t) };
      };
    }
    if (t.kind === 'struct') return this.prepDynStructComponent(a, ctx, out);
    if (t.kind === 'array') return this.prepArrayComponent(a, ctx, out);
    // a static VALUE component: SPILL at position (source-order evaluation; the pre-two-phase
    // {word: expr} form deferred the expression - and its side effects - into the write loop).
    const w = this.fresh();
    out.push(`let ${w} := ${this.lowerExpr(a, ctx, out)}`);
    return () => ({ word: w });
  }

  /** The frozen storage base slot of a STATIC storage aggregate component, or undefined for
   *  non-storage sources. Index/key side effects and bounds checks run here (at the component's
   *  source position); the copy out of storage happens at serialize time. */
  private staticAggStorageSlot(e: Expr, ctx: LowerCtx, out: string[]): string | undefined {
    if (e.kind === 'structValue') return String(e.baseSlot);
    if (e.kind === 'mapStorageValue') return this.mappingSlot(e.baseSlot, e.keys, ctx, out);
    if (e.kind === 'structArrayElem') return this.structArrayElemSlot(e.arr, e.index, ctx, out);
    if (e.kind === 'placeRead') return this.lowerPlace(e.path, ctx, out).slot;
    if (e.kind === 'arrayValue' && e.arr.base.kind === 'fixedArray') return String(e.arr.base.baseSlot);
    return undefined;
  }

  /** W7A phase 1 for a DYNAMIC-STRUCT component: acquire a stable source handle at the component's
   *  position (ctor args evaluate now - live memory refs are captured as pointers into the fresh
   *  pointer-headed image; storage slots freeze; memory sources alias), returning the phase-2
   *  finisher that encodes the head/tail blob LATE through the handle. */
  private prepDynStructComponent(a: Expr, ctx: LowerCtx, out: string[]): (o: string[]) => EncPart {
    const struct = a.type as JethType & { kind: 'struct' };
    // a STORAGE struct: slot at position, encode at serialize time (Cat C direct-from-storage, or
    // the buildDynStructFromStorage copy + mem-src encode - branch selection identical to the
    // pre-two-phase encodeDynStructToBlob, just deferred so the sload's happen post-sibling).
    if (
      a.kind === 'structValue' ||
      a.kind === 'mapStorageValue' ||
      a.kind === 'structArrayElem' ||
      a.kind === 'placeRead'
    ) {
      const slot = this.structSrcSlot(a, ctx, out);
      return (o) => this.encodeDynStructBlobFromStorage(struct, slot, ctx, o);
    }
    // a whole calldata dyn-struct param: immutable, no position effects - materialize + validate late.
    if (a.kind === 'cdDynStructValue') {
      return (o) => this.encodeDynStructToBlob(a, ctx, o);
    }
    // an inline CONSTRUCTOR whose field set the mem-src encoder can serialize: build the native
    // pointer-headed image at position (args evaluate left-to-right; memory-ref args are captured
    // as POINTERS - Solidity reference semantics; static-agg fields freeze with capture patches),
    // then encode from the image LATE - sibling mutations through the captured refs are visible.
    if (a.kind === 'structNew' && this.dynStructMemSrcEncodable(struct)) {
      const headPtr = this.buildDynStructLocal(struct, a, ctx, out);
      return (o) => this.encodeDynStructBlobFromSrc(struct, { kind: 'mem', headPtr }, ctx, o);
    }
    // memory-image sources: freeze the image pointer / run index+call side effects at position,
    // encode late through the pointer (tupleSrc yields a 'mem' handle for all of these).
    if (
      a.kind === 'memDynStructValue' ||
      a.kind === 'arrayGet' ||
      a.kind === 'call' ||
      a.kind === 'ternary' ||
      a.kind === 'memDynField' ||
      a.kind === 'memDynNestedField'
    ) {
      const src = this.tupleSrc(a, ctx, out);
      return (o) => this.encodeDynStructBlobFromSrc(struct, src, ctx, o);
    }
    // anything else (a cd struct-array element with index effects, an unanticipated kind): keep the
    // pre-two-phase at-position encode - behavior unchanged for these rare shapes.
    const blob = this.encodeDynStructToBlob(a, ctx, out);
    return () => blob;
  }

  /** True when every field of `struct` (recursing through nested dyn-struct fields) is encodable
   *  from a pointer-headed MEMORY image ('mem' TupleSrc). A dynamic array with STRUCT elements and
   *  a fixed-outer dynamic array outside the isDynLeafFixedArray family still need the 'new'
   *  source; those constructor components keep the at-position encode. */
  private dynStructMemSrcEncodable(struct: JethType & { kind: 'struct' }): boolean {
    return struct.fields.every((f) => {
      if (f.type.kind === 'array' && f.type.length === undefined && f.type.element.kind === 'struct') return false;
      if (f.type.kind === 'array' && f.type.length !== undefined && isDynamicType(f.type) && !isDynLeafFixedArray(f.type))
        return false;
      if (f.type.kind === 'struct' && isDynamicType(f.type)) return this.dynStructMemSrcEncodable(f.type);
      return true;
    });
  }

  /** Encode a dyn-struct head/tail blob from an already-resolved TupleSrc (the tail half of
   *  encodeDynStructToBlob). All reads go through the src handle - safe to run at serialize time. */
  private encodeDynStructBlobFromSrc(
    struct: JethType & { kind: 'struct' },
    src: TupleSrc,
    ctx: LowerCtx,
    out: string[],
  ): { mp: string; size: string } {
    const queue: DynRef[] = [];
    this.collectTupleDyn(struct, src, queue, ctx, out);
    let qi = 0;
    const nextRef = (): DynRef => queue[qi++]!;
    const mp = this.fresh();
    out.push(`let ${mp} := mload(0x40)`);
    const end = this.encodeTupleInto(struct, src, mp, ctx, out, nextRef);
    out.push(`mstore(0x40, ${end})`);
    return { mp, size: `sub(${end}, ${mp})` };
  }

  /** Encode a STORAGE dyn-struct component's blob from its frozen base slot: the Cat-C
   *  direct-from-storage encoder for nested-dynamic-leaf array fields, else the storage->memory
   *  copy + mem-src encode. Mirrors encodeDynStructToBlob's storage branches exactly. */
  private encodeDynStructBlobFromStorage(
    struct: JethType & { kind: 'struct' },
    slot: string,
    ctx: LowerCtx,
    out: string[],
  ): { mp: string; size: string } {
    if (struct.fields.some((f) => isDynStructLeafArrayField(f.type))) {
      const mp = this.fresh();
      out.push(`let ${mp} := mload(0x40)`);
      const size = this.fresh();
      out.push(`let ${size} := ${this.abiEncFromStorage(struct, slot, 0, mp, out)}`);
      out.push(`mstore(0x40, add(${mp}, ${size}))`);
      return { mp, size };
    }
    const headPtr = this.buildDynStructFromStorage(struct, slot, ctx, out);
    return this.encodeDynStructBlobFromSrc(struct, { kind: 'mem', headPtr }, ctx, out);
  }

  /** ABI-encode a memory image into a fresh tail blob via abiEncFromMem (pure reads through the
   *  image pointers - safe at serialize time). Returns {mp, size}. */
  private abiEncFromMemBlob(t: JethType, img: string, ctx: LowerCtx, out: string[]): { mp: string; size: string } {
    const dst = this.fresh();
    out.push(`let ${dst} := mload(0x40)`);
    const sz = this.fresh();
    out.push(`let ${sz} := ${this.abiEncFromMem(t, img, dst, ctx, out)}`);
    out.push(`mstore(0x40, add(${dst}, ${sz}))`);
    return { mp: dst, size: sz };
  }

  /** Re-encode a resolved calldata header into a fresh ABI tail blob via abiEncFromCd (immutable
   *  source; the validation reverts fire at serialize time, matching solc). Returns {mp, size}. */
  private abiEncFromCdBlob(
    t: JethType,
    hdr: string,
    validate: boolean,
    out: string[],
  ): { mp: string; size: string } {
    const dst = this.fresh();
    out.push(`let ${dst} := mload(0x40)`);
    const sz = this.fresh();
    out.push(`let ${sz} := ${this.abiEncFromCd(t, hdr, dst, validate, out, true)}`);
    out.push(`mstore(0x40, add(${dst}, ${sz}))`);
    return { mp: dst, size: sz };
  }

  /** W7A phase 1 for a DYNAMIC-ARRAY component: freeze the source handle at position (memory
   *  images alias; storage length-slots and calldata headers freeze - index side effects run
   *  now), returning the phase-2 finisher that builds the {mp, size} ABI tail LATE. Branch
   *  taxonomy mirrors materializeArrayArg; the serializing codecs are identical. */
  private prepArrayComponent(a: Expr, ctx: LowerCtx, out: string[]): (o: string[]) => EncPart {
    // a dyn-array field of a calldata dyn-struct array element: header at position (index effects,
    // Panic 0x32), calldata re-encode late (EMPTY-revert decode flavors preserved).
    if (a.kind === 'cdFieldAggValue' || a.kind === 'cdNestedFieldAggValue') {
      const hdr =
        a.kind === 'cdFieldAggValue'
          ? this.cdFieldArrayHeader(a.place, ctx, out)
          : this.cdNestedFieldArrayHeader(a.place, a.indices, ctx, out);
      const validate = !isValueLeafArray(a.type);
      return (o) => this.abiEncFromCdBlob(a.type, hdr, validate, o);
    }
    const memSourced =
      a.kind === 'arrayLit' ||
      a.kind === 'newArray' ||
      (a.kind === 'arrayValue' && (a.arr.base.kind === 'memArray' || a.arr.base.kind === 'memArrayExpr'));
    const codecSourced =
      (isNestedValueArray(a.type) && isDynamicType(a.type)) ||
      isAggregateLeafArray(a.type) ||
      isDynBytesFixedLeafArray(a.type) || // Arr<string,N>/Arr<bytes,N> field read: a memArrayExpr base wrapping the head-word LOAD of the pointer-headed field image (memFixedLen=N)
      isDynStructFixedLeafArray(a.type) || // Arr<In,N> DYNAMIC-struct-element field read: SAME N-pointer field image, SAME encoder as the alias-out / return path (its memArrayExpr base loads the field-image pointer; abiEncFromMem flattens each dyn-struct element - no double-deref, matching whole()/aliasout()/ret())
      (isStaticStructAnyLeafArray(a.type) && isDynamicType(a.type));
    // a memory-image nested/aggregate-leaf array: image pointer at position (a memArray local
    // ALIASES; a literal builds its pointer-headed image now, element refs captured as pointers),
    // abiEncFromMem transcode late (reads through the pointers post-sibling). A fixed-outer
    // bytes/string-leaf field read (isDynBytesFixedLeafArray) rides the SAME nestedMemImagePtr +
    // abiEncFromMem encoder the return path and the aliased-local form already use byte-identically -
    // its memArrayExpr base is the field's N-pointer image, NOT a [len][elems] value array (routing it
    // through the value-array memArrayExpr branch below double-derefs the pointer -> the 0x1840 blob).
    if ((codecSourced && memSourced) || this.isMemFixedDynLeafArg(a)) {
      const img = this.nestedMemImagePtr(a, ctx, out);
      return (o) => this.abiEncFromMemBlob(a.type, img, ctx, o);
    }
    if (
      (a.kind === 'newArray' || a.kind === 'call') &&
      a.type.kind === 'array' &&
      a.type.length === undefined &&
      isStaticValueType(a.type.element)
    ) {
      // a value-element dynamic array produced by `new Array<T>(n)` / an internal call: its
      // [len][elems] image IS the ABI tail. Freeze the pointer at position (the call / length
      // expression runs now); the size reads the length late (immutable in place).
      const m = this.fresh();
      out.push(`let ${m} := ${this.lowerExpr(a, ctx, out)}`);
      return () => ({ mp: m, size: `mul(add(mload(${m}), 1), 0x20)` });
    }
    if (a.kind === 'arrayValue') {
      const base = a.arr.base;
      if (base.kind === 'cdDynArrayField') {
        const hdr = this.cdFieldArrayHeader(base.place, ctx, out);
        const validate = !isValueLeafArray(a.type);
        return (o) => this.abiEncFromCdBlob(a.type, hdr, validate, o);
      }
      if (base.kind === 'cdDynFixedDynField') {
        const hdr = this.cdFieldArrayHeader(base.place, ctx, out);
        const validate = !isValueLeafArray(a.type);
        const len = base.length;
        return (o) => {
          o.push(`if gt(add(${hdr}, ${len * 32}), calldatasize()) { revert(0, 0) }`);
          return this.abiEncFromCdBlob(a.type, hdr, validate, o);
        };
      }
      if (base.kind === 'memArray' || base.kind === 'memArrayExpr') {
        // a memory value-array local / expression: ALIAS the [len][elems] image at position; the
        // W6C enum range-check and the size read run at serialize time (post-sibling).
        const mp = this.fresh();
        const src = base.kind === 'memArray' ? this.ctxLookup(ctx, base.varName) : this.lowerExpr(base.expr, ctx, out);
        out.push(`let ${mp} := ${src}`);
        return (o) => {
          this.validateEnumMemArray(a.type, mp, o);
          const size = this.fresh();
          o.push(`let ${size} := mul(add(mload(${mp}), 1), 0x20)`);
          return { mp, size };
        };
      }
      if (
        base.kind === 'stateArray' ||
        base.kind === 'mapArray' ||
        base.kind === 'placeArray' ||
        base.kind === 'fixedArray'
      ) {
        // a STORAGE array: freeze the length slot at position (mapping keys / place indices run
        // now), copy out of storage at serialize time (solc reads post-sibling - probe P1).
        let lenSlot: string;
        if (base.kind === 'stateArray') lenSlot = String(base.slot);
        else if (base.kind === 'mapArray') lenSlot = this.mappingSlot(base.baseSlot, base.keys, ctx, out);
        else if (base.kind === 'placeArray') lenSlot = this.lowerPlace(base.path, ctx, out).slot;
        else lenSlot = String((base as { baseSlot: bigint }).baseSlot);
        return (o) => {
          const sdst = this.fresh();
          o.push(`let ${sdst} := mload(0x40)`);
          const ssz = this.abiEncFromStorage(a.type, lenSlot, 0, sdst, o);
          const sm = this.fresh();
          o.push(`let ${sm} := ${ssz}`);
          o.push(`mstore(0x40, add(${sdst}, ${sm}))`);
          return { mp: sdst, size: sm };
        };
      }
      if (base.kind === 'calldataArray') {
        // a whole calldata array param: immutable, no position effects; the validating echo runs
        // at serialize time (its reverts fire post-sibling, the solc model).
        return (o) => {
          const { ptr, size } = this.echoParam((base as { name: string }).name, a.type, ctx, o, true);
          const mp = this.fresh();
          o.push(`let ${mp} := add(${ptr}, 0x20)`);
          const sz = this.fresh();
          o.push(`let ${sz} := sub(${size}, 0x20)`);
          return { mp, size: sz };
        };
      }
      // cdSlice and any other base: keep the pre-two-phase at-position materialization.
      const r = this.materializeArrayArg(a, ctx, out);
      return () => r;
    }
    // any other kind: preserve the pre-two-phase behavior (at-position materialization / the
    // JETH900 reject for genuinely unsupported shapes).
    const r = this.materializeArrayArg(a, ctx, out);
    return () => r;
  }

  /** Packed encoding (abi.encodePacked) as a bytes value: each value contributes its byte-width
   *  (no padding/length), each bytes/string its raw content. The final partial word is zeroed so the
   *  bytes value's tail padding is clean (a slack word is allocated to keep that write in-bounds).
   *
   *  Each part is normalized to a (dataPtr, byteLen) descriptor SPILLED to a memory array, then copied
   *  in a runtime loop. This keeps only a constant number of Yul locals live regardless of arg count -
   *  the previous version kept one local per part across the whole encode, so a long encodePacked / a
   *  many-part string.concat / a 3+-interpolation template overflowed the 16-slot stack (StackTooDeep).
   *  The descriptor array is allocated FIRST so part materializations (which bump the free pointer) never
   *  clobber it, and the result buffer is allocated LAST. Intermediate memory differs from solc's, but the
   *  RESULT bytes are identical (byte-identity targets returndata/storage/logs, not raw memory). */
  private buildAbiEncodePacked(args: Expr[], ctx: LowerCtx, out: string[]): string {
    const n = args.length;
    // descriptor array: n entries of (dataPtr, byteLen), allocated before any part materializes.
    const desc = this.fresh();
    out.push(`let ${desc} := ${this.alloc()}(${Math.max(n, 1) * 0x40})`);
    const total = this.fresh();
    out.push(`let ${total} := 0`);
    const writeDesc = (i: number, dataPtr: string, len: string) => {
      const dpSlot = i === 0 ? desc : `add(${desc}, ${i * 0x40})`;
      out.push(`mstore(${dpSlot}, ${dataPtr})`);
      out.push(`mstore(add(${desc}, ${i * 0x40 + 0x20}), ${len})`);
      out.push(`${total} := add(${total}, ${len})`);
    };
    // W7A TWO-PHASE: each part evaluates LEFT-TO-RIGHT at its source position; anything whose
    // CONTENT solc reads at serialize time is deferred to a finish pass after every part's side
    // effects (storage/calldata bytes copies, storage array copies, enum range checks - probe P7:
    // a storage array part reads post-sibling storage). Parts that are already late-reading stay
    // fully at-position and keep NO live Yul locals across the encode: a VALUE part is frozen into
    // its scratch word at its position (value semantics - identical before/after), and a MEMORY
    // bytes part's descriptor holds a live data pointer whose content the FINAL copy loop reads
    // late anyway. (Spilling those to locals re-created the StackTooDeep the descriptor-array
    // design exists to prevent: a 10-interpolation template = 10+ live locals.)
    const prevPatches = this.beginTwoPhase();
    const preps: ((o: string[]) => void)[] = [];
    args.forEach((a, i) => {
      const t = a.type;
      if (isBytesLike(t)) {
        const ref = this.lowerDynamic(a, ctx, out);
        if (ref.src === 'memory') {
          // descriptor -> the live [len][data] pointer; the final copy loop reads content LATE.
          writeDesc(i, `add(${ref.ptr}, 0x20)`, `mload(${ref.ptr})`);
        } else {
          // storage/calldata: the copy out of the source runs at serialize time (late reads).
          preps.push((o) => {
            const { mp, len } = this.toMemory(ref, o);
            writeDesc(i, `add(${mp}, 0x20)`, len);
          });
        }
      } else if (t.kind === 'array' && t.length !== undefined && !isDynamicType(t)) {
        // a static fixed array: freeze the handle at position (storage slot / memory alias / ctor
        // image with capture patches); copy out of storage + range-check enums at serialize time.
        const slot = this.staticAggStorageSlot(a, ctx, out);
        if (slot !== undefined) {
          preps.push((o) => writeDesc(i, this.allocAggFromStorage(t, slot, o), String((t.length as number) * 32)));
        } else {
          const pm = this.aggToMemPtr(a, ctx, out);
          preps.push((o) => {
            // W6C: a fixed ENUM array is range-checked before its words enter the packed blob
            // (Panic 0x21) - a bound memory local may hold RAW dirty words from the bind copy.
            this.validateEnumMemArray(t, pm, o);
            writeDesc(i, pm, String((t.length as number) * 32));
          });
        }
      } else if (t.kind === 'array') {
        // a dynamic array: handle at position, ABI tail built late.
        const finish = this.prepArrayComponent(a, ctx, out);
        preps.push((o) => {
          const m = finish(o) as { mp: string; size: string };
          writeDesc(i, `add(${m.mp}, 0x20)`, `sub(${m.size}, 0x20)`);
        });
      } else {
        // a value: stage its left-aligned `width` content bytes in a scratch word AT ITS POSITION
        // (frozen value semantics; no local survives the part), descriptor -> that word.
        const width = storageByteSize(t);
        const val = this.lowerExpr(a, ctx, out);
        const aligned = t.kind === 'bytesN' || width === 32 ? val : `shl(${(32 - width) * 8}, ${val})`;
        const w = this.fresh();
        out.push(`let ${w} := ${this.alloc()}(0x20)`);
        out.push(`mstore(${w}, ${aligned})`);
        writeDesc(i, w, String(width));
      }
    });
    this.flushTwoPhase(prevPatches, out);
    preps.forEach((f) => f(out));
    // allocate the result LAST (length word + rounded data + a slack word for the trailing zero).
    const ptr = this.fresh();
    out.push(`let ${ptr} := ${this.alloc()}(add(0x40, and(add(${total}, 0x1f), not(0x1f))))`);
    out.push(`mstore(${ptr}, ${total})`);
    const cursor = this.fresh();
    out.push(`let ${cursor} := add(${ptr}, 0x20)`);
    if (n > 0) {
      const i = this.fresh();
      const dp = this.fresh();
      const ln = this.fresh();
      out.push(`for { let ${i} := 0 } lt(${i}, ${n * 0x40}) { ${i} := add(${i}, 0x40) } {`);
      out.push(`  let ${dp} := mload(add(${desc}, ${i}))`);
      out.push(`  let ${ln} := mload(add(add(${desc}, ${i}), 0x20))`);
      out.push(`  mcopy(${cursor}, ${dp}, ${ln})`);
      out.push(`  ${cursor} := add(${cursor}, ${ln})`);
      out.push(`}`);
    }
    out.push(`mstore(${cursor}, 0)`); // zero the trailing partial word
    return ptr;
  }

  private lowerDynamic(e: Expr, ctx: LowerCtx, out: string[]): DynRef {
    switch (e.kind) {
      case 'rawReg':
        // a pre-computed register holding a [len][data] MEMORY pointer (e.g. the buffered modifier
        // return reg, set from userfn_<key> which returns a bytes/string aggregate as a memory ptr).
        return { src: 'memory', ptr: e.reg };
      case 'cast':
        // bytes(string) / string(bytes): a no-op reinterpret of the same [len][data] dynamic value.
        return this.lowerDynamic(e.operand, ctx, out);
      case 'dynStateRead':
        return { src: 'storage', slot: String(e.slot) };
      case 'mapDynValue': {
        // this.m[k] where the value is bytes/string: the dynamic value lives at the
        // runtime keccak(key.base) mapping slot (short inline / long at keccak(slot)).
        const slot = this.mappingSlot(e.baseSlot, e.keys, ctx, out);
        return { src: 'storage', slot };
      }
      case 'dynParamRead': {
        const b = ctx.dynParams.get(e.name);
        if (!b) throw new UnsupportedError(`unbound dynamic param ${e.name}`);
        return { src: 'calldata', dataPtr: b.dataPtr, len: b.len };
      }
      case 'msgData':
        // msg.data is the WHOLE calldata (selector included), so data starts at 0 and
        // length is calldatasize() (matches solc: msg.data.length == calldatasize()).
        return { src: 'calldata', dataPtr: '0', len: 'calldatasize()' };
      case 'calldataSlice': {
        // <calldata bytes>.slice(start[, end]) -> a zero-copy sub-view: dataPtr+start, len = end-start.
        // Byte-identical to solc data[start:end]: require(start <= end && end <= baseLen) else revert EMPTY.
        // Order: lower the base, then start, then end (matching solc left-to-right operand evaluation).
        const ref = this.lowerDynamic(e.base, ctx, out);
        if (ref.src !== 'calldata') throw new UnsupportedError('calldataSlice base must be a calldata bytes value');
        const baseData = this.fresh();
        const baseLen = this.fresh();
        out.push(`let ${baseData} := ${ref.dataPtr}`);
        out.push(`let ${baseLen} := ${ref.len}`);
        const start = this.fresh();
        out.push(`let ${start} := ${this.lowerExpr(e.start, ctx, out)}`);
        const end = this.fresh();
        if (e.end) out.push(`let ${end} := ${this.lowerExpr(e.end, ctx, out)}`);
        else out.push(`let ${end} := ${baseLen}`);
        out.push(`if gt(${start}, ${end}) { revert(0, 0) }`);
        out.push(`if gt(${end}, ${baseLen}) { revert(0, 0) }`);
        const dataPtr = this.fresh();
        const len = this.fresh();
        out.push(`let ${dataPtr} := add(${baseData}, ${start})`);
        out.push(`let ${len} := sub(${end}, ${start})`);
        return { src: 'calldata', dataPtr, len };
      }
      case 'abiEncode':
        return { src: 'memory', ptr: this.buildAbiEncode(e.args, e.packed, ctx, out, e.selector, e.sig) };
      case 'abiDecode':
        // abi.decode(data, T) / data.decode(T) with a bytes/string T: the decoded value is a fresh
        // memory [len][data] image; the single component register is its pointer.
        return { src: 'memory', ptr: this.lowerAbiDecode(e.data, [e.type], ctx, out)[0]! };
      case 'extCode': {
        // <addr>.code -> the deployed bytecode as a fresh bytes blob (EXTCODESIZE + EXTCODECOPY).
        // (codehash is a single word, handled in lowerExpr; this case is only the `code` member.)
        const a = this.fresh();
        out.push(`let ${a} := ${this.lowerExpr(e.addr, ctx, out)}`);
        const sz = this.fresh();
        out.push(`let ${sz} := extcodesize(${a})`);
        const ptr = this.fresh();
        out.push(`let ${ptr} := ${this.alloc()}(add(0x20, and(add(${sz}, 0x1f), not(0x1f))))`);
        out.push(`mstore(${ptr}, ${sz})`);
        out.push(`extcodecopy(${a}, add(${ptr}, 0x20), 0, ${sz})`);
        out.push(`if mod(${sz}, 0x20) { mstore(add(add(${ptr}, 0x20), ${sz}), 0) }`);
        return { src: 'memory', ptr };
      }
      case 'cloneArgs': {
        // OZ Clones.fetchCloneArgs(address(this)) = own code[0x2d:]: this clone's appended immutable args.
        // argsLen = extcodesize(address()) - 0x2d (a non-clone / no-args clone yields a 0-length blob; an
        // impl whose own code is shorter than 0x2d would underflow, but cloneArgs is only meaningful when
        // running as a clone, so sub is correct - matches OZ, which has the same precondition).
        const sz = this.fresh();
        out.push(`let ${sz} := sub(extcodesize(address()), 0x2d)`);
        const ptr = this.fresh();
        out.push(`let ${ptr} := ${this.alloc()}(add(0x20, and(add(${sz}, 0x1f), not(0x1f))))`);
        out.push(`mstore(${ptr}, ${sz})`);
        out.push(`extcodecopy(address(), add(${ptr}, 0x20), 0x2d, ${sz})`);
        out.push(`if mod(${sz}, 0x20) { mstore(add(add(${ptr}, 0x20), ${sz}), 0) }`);
        return { src: 'memory', ptr };
      }
      case 'modexp': {
        // modexp(base, exp, mod) (precompile 0x05). Materialize each operand to memory FIRST (an
        // allocating arg must not bump the FMP between the input alloc and the mcopies), then build the
        // input blob 32B Bsize || 32B Esize || 32B Msize || base || exp || mod (unpadded totalIn passed to
        // staticcall), revert EMPTY on ok=0, capture the returndata into a fresh [len][data] blob.
        const b = this.toMemory(this.lowerDynamic(e.base, ctx, out), out);
        const ex = this.toMemory(this.lowerDynamic(e.exp, ctx, out), out);
        const md = this.toMemory(this.lowerDynamic(e.mod, ctx, out), out);
        const total = this.fresh();
        out.push(`let ${total} := add(0x60, add(${b.len}, add(${ex.len}, ${md.len})))`);
        const inp = this.fresh();
        out.push(`let ${inp} := ${this.alloc()}(${total})`);
        out.push(`mstore(${inp}, ${b.len})`);
        out.push(`mstore(add(${inp}, 0x20), ${ex.len})`);
        out.push(`mstore(add(${inp}, 0x40), ${md.len})`);
        out.push(`mcopy(add(${inp}, 0x60), add(${b.mp}, 0x20), ${b.len})`);
        out.push(`mcopy(add(add(${inp}, 0x60), ${b.len}), add(${ex.mp}, 0x20), ${ex.len})`);
        out.push(`mcopy(add(add(add(${inp}, 0x60), ${b.len}), ${ex.len}), add(${md.mp}, 0x20), ${md.len})`);
        out.push(`if iszero(staticcall(gas(), 0x05, ${inp}, ${total}, 0, 0)) { revert(0, 0) }`);
        const ptr = this.captureReturndata(out);
        return { src: 'memory', ptr };
      }
      case 'blake2f': {
        // blake2f(rounds:u32, h(64), m(128), t:bytes16, f:bool) (precompile 0x09). Build the 213-byte
        // EIP-152 blob: rounds(4 BE) | h(64) | m(128) | t(16) | f(1). h/m length-guards revert EMPTY.
        const h = this.toMemory(this.lowerDynamic(e.h, ctx, out), out);
        const m = this.toMemory(this.lowerDynamic(e.m, ctx, out), out);
        out.push(`if iszero(eq(${h.len}, 64)) { revert(0, 0) }`);
        out.push(`if iszero(eq(${m.len}, 128)) { revert(0, 0) }`);
        const rounds = this.lowerExpr(e.rounds, ctx, out);
        const t = this.lowerExpr(e.t, ctx, out);
        const f = this.lowerExpr(e.f, ctx, out);
        // allocate the 64-byte output bytes blob FIRST (so the t-store's zero-write past byte 212 cannot
        // touch it); then the 213-byte input blob.
        const o = this.fresh();
        out.push(`let ${o} := ${this.alloc()}(0x60)`);
        out.push(`mstore(${o}, 64)`);
        const p = this.fresh();
        out.push(`let ${p} := ${this.alloc()}(213)`);
        out.push(`mstore(${p}, shl(224, ${rounds}))`);
        out.push(`mcopy(add(${p}, 4), add(${h.mp}, 0x20), 64)`);
        out.push(`mcopy(add(${p}, 68), add(${m.mp}, 0x20), 128)`);
        out.push(`mstore(add(${p}, 196), ${t})`);
        out.push(`mstore8(add(${p}, 212), ${f})`);
        out.push(`if iszero(staticcall(gas(), 9, ${p}, 213, add(${o}, 0x20), 64)) { revert(0, 0) }`);
        return { src: 'memory', ptr: o };
      }
      case 'callData':
        // this.data inside a success condition: the returndata blob pointer bound for this check.
        return { src: 'memory', ptr: this.ctxLookup(ctx, EXT_CALL_DATA_BINDING) };
      case 'catchReason':
        // `this.reason` inside a try/catch catch body: the SOFT-decoded Error(string).
        return { src: 'memory', ptr: this.lowerCatchReason(ctx, out) };
      case 'extCall': {
        // perform the CALL/STATICCALL, then run the ordered success checks (the first failing
        // condition reverts with its reason). Yields the returndata bytes.
        const { okReg, dataPtr } = this.emitExtCall(e, ctx, out);
        this.lowerSuccessChecks(e.checks, okReg, dataPtr, ctx, out);
        return { src: 'memory', ptr: dataPtr };
      }
      case 'call': {
        // a bytes/string-returning internal call: the callee returns a [len][data] memory pointer.
        const p = this.fresh();
        out.push(`let ${p} := ${this.lowerExpr(e, ctx, out)}`);
        return { src: 'memory', ptr: p };
      }
      case 'ternary': {
        // a bytes/string ternary `c ? a : b`: short-circuit (only the taken branch is
        // materialized), then select the [len][data] pointer. Matches Solidity (the untaken
        // branch is not evaluated, so a reverting/side-effecting branch is safe).
        const c = this.lowerExpr(e.cond, ctx, out);
        const ptr = this.fresh();
        out.push(`let ${ptr} := 0`);
        // W7A: suspend capture-patch recording inside the switch-case branch blocks.
        const thenOut: string[] = [];
        const { mp: mpT } = this.withoutCapturePatches(() =>
          this.toMemory(this.lowerDynamic(e.then, ctx, thenOut), thenOut),
        );
        const elseOut: string[] = [];
        const { mp: mpE } = this.withoutCapturePatches(() =>
          this.toMemory(this.lowerDynamic(e.else, ctx, elseOut), elseOut),
        );
        out.push(`switch ${c}`);
        out.push('case 0 {');
        for (const l of elseOut) out.push('  ' + l);
        out.push(`  ${ptr} := ${mpE}`);
        out.push('}');
        out.push('default {');
        for (const l of thenOut) out.push('  ' + l);
        out.push(`  ${ptr} := ${mpT}`);
        out.push('}');
        return { src: 'memory', ptr };
      }
      case 'dynLocalRead':
        // a bytes/string MEMORY local: its register IS the [len][data] pointer.
        return { src: 'memory', ptr: this.ctxLookup(ctx, e.name) };
      case 'memDynField': {
        // a bytes/string field of a memory dynamic struct: the head word holds the
        // [len][data] pointer.
        const head = this.ctxLookup(ctx, e.local);
        const at = e.wordOffset === 0 ? head : `add(${head}, ${e.wordOffset * 32})`;
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(${at})`);
        return { src: 'memory', ptr };
      }
      case 'memDynNestedField': {
        // a bytes/string/dyn-array/nested-dyn-struct leaf of a NESTED dynamic struct (v.t.s, v.t.u): deref
        // the chain to the inner image, then the final head word holds the blob/array/sub-image pointer.
        const inner = this.nestedInnerPtr(e.local, e.derefWords, ctx, out);
        const at = e.finalWord === 0 ? inner : `add(${inner}, ${e.finalWord * 32})`;
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(${at})`);
        return { src: 'memory', ptr };
      }
      case 'aggFieldRead': {
        // Residual B3: a bytes/string field of a memory-array dyn-struct element (xs[i].s). With deref,
        // aggFieldRead lowers to the head word VALUE = the [len][data] blob's absolute pointer.
        const ptr = this.fresh();
        out.push(`let ${ptr} := ${this.lowerExpr(e, ctx, out)}`);
        return { src: 'memory', ptr };
      }
      case 'strArrayElem': {
        // Residual B2: a MEMORY bytes[]/string[] element (bs[i]). The element word holds an absolute
        // pointer to a [len][data] blob; lowerArrayGet (memory branch, pointer-load for a bytes element)
        // returns that pointer directly. Bounds-check is inside lowerArrayGet (Panic 0x32).
        if (e.arr.base.kind === 'memArray' || e.arr.base.kind === 'memArrayExpr') {
          const ptr = this.fresh();
          out.push(`let ${ptr} := ${this.lowerArrayGet({ kind: 'arrayGet', type: e.type, arr: e.arr, index: e.index }, ctx, out)}`);
          return { src: 'memory', ptr };
        }
        // storage / mapping-valued string[]/bytes[] element: bounds-check i (Panic
        // 0x32), then the element header at keccak(lenSlot)+i is a normal storage
        // bytes/string (short inline / long with keccak(headerSlot) data slots).
        const slot = this.strArrayElemSlot(e.arr, e.index, ctx, out, e.oobEmpty);
        return { src: 'storage', slot };
      }
      case 'dynPlaceRead': {
        // bytes/string field of a storage dynamic struct (this.d.s, this.recs[i].s,
        // this.m[k].s): fold the AccessPath to the field's slot (struct base +
        // field slot, with any index/key bound-check & keccak applied), then read it
        // as a normal storage bytes/string. The field offset is always 0 (whole-slot).
        const p = this.lowerPlace(e.path, ctx, out);
        return { src: 'storage', slot: p.slot };
      }
      case 'cdDynArrayElem': {
        // string[]/bytes[] element: bounds-check i (Panic 0x32), then decode the
        // i-th element's dynamic value via the per-element offset table.
        const ref = this.lowerArrayRef(e.arr, ctx, out);
        if (ref.src !== 'calldata') throw new UnsupportedError('string[]/bytes[] element requires a calldata array');
        const i = this.fresh();
        out.push(`let ${i} := ${this.lowerExpr(e.index, ctx, out)}`);
        out.push(`if iszero(lt(${i}, ${ref.length})) { ${this.panic()}(0x32) }`);
        const dataPtr = this.fresh();
        const len = this.fresh();
        out.push(`let ${dataPtr}, ${len} := ${this.calldataDynElem()}(${ref.offset}, ${i})`);
        return { src: 'calldata', dataPtr, len };
      }
      case 'cdDynStructField': {
        // bytes/string dynamic field of a dynamic-struct calldata param. The field's
        // head slot holds an offset word relative to the containing tuple start; the
        // value (length + payload) is at base + offset (spec section 3.2).
        const base = this.lowerCdDynBase(e.place, ctx, out);
        const last = e.place.steps[e.place.steps.length - 1]!;
        const offPtr = last.headWords === 0 ? base : `add(${base}, ${last.headWords * 32})`;
        const dataPtr = this.fresh();
        const len = this.fresh();
        out.push(`let ${dataPtr}, ${len} := ${this.calldataDynAt()}(${base}, ${offPtr})`);
        return { src: 'calldata', dataPtr, len };
      }
      case 'stringLiteral': {
        const ptr = this.fresh();
        const len = e.bytes.length;
        const nwords = Math.ceil(len / 32);
        out.push(`let ${ptr} := ${this.alloc()}(${0x20 + nwords * 32})`);
        out.push(`mstore(${ptr}, ${len})`);
        for (let i = 0; i < nwords; i++) {
          out.push(`mstore(add(${ptr}, ${0x20 + i * 32}), ${wordFromBytes(e.bytes, i * 32)})`);
        }
        return { src: 'memory', ptr };
      }
      default:
        throw new UnsupportedError(`not a dynamic value: ${e.kind}`);
    }
  }

  /** Length (uint256) of a dynamic value. */
  private dynLen(ref: DynRef): string {
    if (ref.src === 'storage') return `${this.strLen()}(${ref.slot})`;
    if (ref.src === 'calldata') return ref.len;
    return `mload(${ref.ptr})`;
  }

  /** Materialize any dynamic value into memory as [len][data...]; returns (mp, len) temps.
   *  This is only reached on LAZY paths (a single bytes/string returned/echoed, or an
   *  event/custom-error arg): the calldata source has already been fully validated by its
   *  decode helper (calldataDyn / calldataDynAt / calldataDynElem - signed offset, length
   *  cap, signed payload-fits), and the byte length is therefore bounded by calldatasize,
   *  so the copy is a plain calldatacopy with no further alloc/payload check (which would
   *  diverge from solc: e.g. an empty string behind a wrapped-pointer offset). The
   *  decode-to-fresh-memory ECHO encoders apply the Panic(0x41)/payload-fits themselves. */
  private toMemory(ref: DynRef, out: string[]): { mp: string; len: string } {
    if (ref.src === 'memory') return { mp: ref.ptr, len: `mload(${ref.ptr})` };
    const mp = this.fresh();
    const len = this.fresh();
    if (ref.src === 'storage') {
      out.push(`let ${mp}, ${len} := ${this.loadStr()}(${ref.slot})`);
    } else {
      out.push(`let ${len} := ${ref.len}`);
      out.push(`let ${mp} := ${this.alloc()}(add(0x20, and(add(${len}, 0x1f), not(0x1f))))`);
      out.push(`mstore(${mp}, ${len})`);
      out.push(`calldatacopy(add(${mp}, 0x20), ${ref.dataPtr}, ${len})`);
      // zero the partial-word tail so padding is clean
      out.push(`if mod(${len}, 0x20) { mstore(add(add(${mp}, 0x20), ${len}), 0) }`);
    }
    return { mp, len };
  }

  /** The raw solc `ecrecover` expansion: staticcall(0x01) over [hash | left-padded-v | r | s] (128 bytes)
   *  into a FRESH free-memory buffer (avoids the 0x40/0x60 scratch clobber). Returns a register holding the
   *  recovered address, or 0 on ANY failure - NEVER reverts. The `and(success, eq(returndatasize(),0x20))`
   *  guard is mandatory: the precompile writes NOTHING on failure, so an unguarded mload leaks stale memory.
   *  Reused by the raw `ecrecover`, the safe `recover`, and the never-reverting `tryRecover`. */
  private emitEcrecover(hash: string, v: string, r: string, s: string, out: string[]): string {
    const p = this.fresh();
    const res = this.fresh();
    out.push(`let ${p} := mload(0x40)`);
    out.push(`mstore(${p}, ${hash})`);
    out.push(`mstore(add(${p}, 0x20), and(${v}, 0xff))`);
    out.push(`mstore(add(${p}, 0x40), ${r})`);
    out.push(`mstore(add(${p}, 0x60), ${s})`);
    out.push(`let ${res} := 0`);
    // Bind the staticcall success to a variable FIRST: Yul evaluates an `and(a, b)`'s arguments
    // right-to-left, so an inline `and(staticcall(...), eq(returndatasize(),0x20))` would read the
    // STALE (pre-call) returndatasize and always discard the result. solc's expansion splits it too.
    const ok = this.fresh();
    out.push(`let ${ok} := staticcall(gas(), 1, ${p}, 0x80, ${p}, 0x20)`);
    out.push(`if and(${ok}, eq(returndatasize(), 0x20)) { ${res} := mload(${p}) }`);
    return res;
  }

  /** Copy the current returndata into a FRESH [len][data] memory bytes blob (length-word at the returned
   *  pointer), tail-zeroing a partial last word. Used by modexp (the precompile returns Msize raw bytes). */
  private captureReturndata(out: string[]): string {
    const dataPtr = this.fresh();
    const rlen = this.fresh();
    out.push(`let ${rlen} := returndatasize()`);
    out.push(`let ${dataPtr} := ${this.alloc()}(add(0x20, and(add(${rlen}, 0x1f), not(0x1f))))`);
    out.push(`mstore(${dataPtr}, ${rlen})`);
    out.push(`returndatacopy(add(${dataPtr}, 0x20), 0, ${rlen})`);
    out.push(`if mod(${rlen}, 0x20) { mstore(add(add(${dataPtr}, 0x20), ${rlen}), 0) }`);
    return dataPtr;
  }

  // --- Phase 1 proxies: EIP-1167 minimal-proxy creation code (byte-identical to OZ Clones 5.1) ---
  //
  // Plain creation (0x37 = 55 bytes) = `3d602d80600a3d3981f3` (10-byte init: returns the 45-byte runtime)
  //   ++ `363d3d373d3d3d363d73<impl:20>5af43d82803e903d91602b57fd5bf3` (45-byte EIP-1167 runtime).
  //   Laid out as two left-aligned words at ptr:
  //     w0 = 0x3d602d80600a3d3981f3363d3d373d3d3d363d73<00*12> | shr(64, impl)   (PRE20 + impl high 12)
  //     w1 = shl(192, impl) | 0x5af43d82803e903d91602b57fd5bf3<00*9>            (impl low 8 + POST15)
  //
  // Immutable-args creation (OZ 5.1 cloneWithImmutableArgs) = `61<len:2>3d81600a3d39f3` (10-byte modified
  //   init that returns runtime+args, len = 0x2d + args.length) ++ the 45-byte runtime ++ <args>. The head
  //   skeleton word w0 swaps the init bytes and OR-s the len in at byte offset 1 (shl(232, len)); w1 is the
  //   SAME as plain; then args are mcopied at offset 55. (Appending args to the PLAIN init does NOT work -
  //   the plain init returns only 45 bytes, dropping the args.)

  /** Materialize the EIP-1167 clone creation code at a fresh memory pointer (32-byte aligned head). Returns
   *  the pointer and a register holding the creation-code byte length (0x37, or 0x37+argLen with args). */
  private buildCloneCreationCode(
    impl: Expr,
    args: Expr | undefined,
    ctx: LowerCtx,
    out: string[],
  ): { ptr: string; len: string } {
    // Lower the impl to a clean 160-bit address register (mask high bits so the OR-injection is exact).
    const implReg = this.fresh();
    out.push(`let ${implReg} := and(${this.lowerExpr(impl, ctx, out)}, 0xffffffffffffffffffffffffffffffffffffffff)`);
    // The POST15 constant (the EIP-1167 runtime suffix) at byte offset 8 within w1 (== << 72).
    const W1_POST = '0x5af43d82803e903d91602b57fd5bf3000000000000000000';
    const len = this.fresh();
    if (!args) {
      // Plain: head is exactly 0x37 bytes; allocate a 0x40-byte aligned head (the second word's 9 trailing
      // zero bytes are inside the alloc and never read by CREATE, which uses only [ptr, ptr+0x37)).
      const ptr = this.fresh();
      out.push(`let ${ptr} := ${this.alloc()}(0x40)`);
      out.push(
        `mstore(${ptr}, or(0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000, shr(64, ${implReg})))`,
      );
      out.push(`mstore(add(${ptr}, 0x20), or(shl(192, ${implReg}), ${W1_POST}))`);
      out.push(`let ${len} := 0x37`);
      return { ptr, len };
    }
    // Immutable args: materialize the args bytes to memory FIRST (an allocating arg must not bump the FMP
    // between the head alloc and the args mcopy).
    const a = this.toMemory(this.lowerDynamic(args, ctx, out), out);
    const argLen = a.len;
    out.push(`let ${len} := add(0x37, ${argLen})`);
    // The PUSH2 length field baked into the modified init = 0x2d + argLen.
    const rtLen = this.fresh();
    out.push(`let ${rtLen} := add(0x2d, ${argLen})`);
    // Allocate head (0x40 aligned) + the args region; over-allocate to a word multiple so the tail is clean.
    const ptr = this.fresh();
    out.push(`let ${ptr} := ${this.alloc()}(add(0x40, and(add(${argLen}, 0x1f), not(0x1f))))`);
    // w0 skeleton (init bytes with the len field zeroed) | shr(64, impl) | shl(232, rtLen).
    out.push(
      `mstore(${ptr}, or(or(0x6100003d81600a3d39f3363d3d373d3d3d363d73000000000000000000000000, shr(64, ${implReg})), shl(232, ${rtLen})))`,
    );
    out.push(`mstore(add(${ptr}, 0x20), or(shl(192, ${implReg}), ${W1_POST}))`);
    // append the immutable args at byte offset 55 (0x37).
    out.push(`mcopy(add(${ptr}, 0x37), add(${a.mp}, 0x20), ${argLen})`);
    return { ptr, len };
  }

  /** clone* / cloneDeterministic* / *WithArgs: deploy an EIP-1167 clone via CREATE (salt unset) or CREATE2
   *  (salt set). A zero result (deployment failure) reverts EMPTY (the OZ failure path is a custom-error
   *  revert; the spec gates the success-path bytes and accepts a clean empty revert on the degenerate
   *  failure). Returns a register holding the new clone address. */
  /** Phase 2a: lower proxyInit / upgradeProxy (the EIP-1967 upgrade primitive, byte-identical to OZ
   *  ERC1967Utils.upgradeToAndCall). Both share: require(isContract(impl)) -> store the EIP-1967 impl
   *  slot -> emit Upgraded(impl) -> if data.length>0 delegatecall(impl, data) and BUBBLE the revert.
   *  proxyInit's admin form additionally writes the EIP-1967 admin slot first. Address operands are
   *  masked to 160 bits before the extcodesize check + store (a clean address in the slot). */
  private lowerProxyMutate(e: Expr & { kind: 'proxyInit' | 'upgradeProxy' }, ctx: LowerCtx, out: string[]): void {
    const MASK = '0xffffffffffffffffffffffffffffffffffffffff';
    // Evaluate operands left-to-right, exactly as written: impl (then admin for the 3-arg proxyInit),
    // then the data bytes are materialized just before the delegatecall.
    const impl = this.fresh();
    out.push(`let ${impl} := and(${this.lowerExpr(e.impl, ctx, out)}, ${MASK})`);
    if (e.kind === 'proxyInit' && e.admin) {
      const admin = this.fresh();
      out.push(`let ${admin} := and(${this.lowerExpr(e.admin, ctx, out)}, ${MASK})`);
      out.push(`sstore(${EIP1967_ADMIN_SLOT}, ${admin})`);
    }
    // require(isContract(impl)): OZ ERC1967InvalidImplementation -> here a clean empty revert (the
    // failure path is degenerate; the success-path bytes are what we byte-match).
    out.push(`if iszero(extcodesize(${impl})) { revert(0, 0) }`);
    out.push(`sstore(${EIP1967_IMPL_SLOT}, ${impl})`);
    // emit Upgraded(address indexed implementation): an indexed-only event, so log2 over no data.
    out.push(`log2(0, 0, ${UPGRADED_TOPIC}, ${impl})`);
    // if data.length>0: delegatecall(gas(), impl, data, 0, 0) and bubble the callee's revert verbatim.
    const data = e.kind === 'proxyInit' ? e.initData : e.data;
    const { mp, len } = this.toMemory(this.lowerDynamic(data, ctx, out), out);
    out.push(`if gt(${len}, 0) {`);
    const ok = this.fresh();
    out.push(`  let ${ok} := delegatecall(gas(), ${impl}, add(${mp}, 0x20), ${len}, 0, 0)`);
    out.push(`  returndatacopy(0, 0, returndatasize())`);
    out.push(`  if iszero(${ok}) { revert(0, returndatasize()) }`);
    out.push(`}`);
  }

  // ---- Phase 3 DIAMOND helpers ----------------------------------------------------------------

  /** The absolute storage slot of a synthesized diamond-storage field by name (base + relative slot).
   *  The five fields are laid out from the raw diamond-storage base by planNamespacedStorage. */
  private diamondSlot(name: string): bigint {
    const v = this.contract?.stateVars.find((s) => s.name === name);
    if (v === undefined) throw new UnsupportedError(`internal: diamond storage field '${name}' missing`);
    return v.slot;
  }

  /** Lower diamondInit(owner): the @diamond constructor primitive (byte-identical to mudgen's
   *  LibDiamond.setContractOwner + DiamondInit's ERC-165 registration). Sets contractOwner = owner,
   *  emits OwnershipTransferred(address(0), owner) (both args indexed, log3 over no data), then sets
   *  supportedInterfaces[id] = true for the four diamond interface ids. */
  private lowerDiamondInit(e: Expr & { kind: 'diamondInit' }, ctx: LowerCtx, out: string[]): void {
    const MASK = '0xffffffffffffffffffffffffffffffffffffffff';
    const owner = this.fresh();
    out.push(`let ${owner} := and(${this.lowerExpr(e.owner, ctx, out)}, ${MASK})`);
    out.push(`sstore(${String(this.diamondSlot('_contractOwner'))}, ${owner})`);
    // emit OwnershipTransferred(address(0) indexed, owner indexed): both args indexed -> log3, no data.
    out.push(`log3(0, 0, ${OWNERSHIP_TRANSFERRED_TOPIC}, 0, ${owner})`);
    // supportedInterfaces[id] = true: mapping(bytes4=>bool) at the field slot; the key (a bytes4) is
    // stored LEFT-aligned (shl 224), then keccak(key . slot), sstore(slot, 1). Matches solc's mapping.
    const siSlot = String(this.diamondSlot('_supportedInterfaces'));
    for (const id of DIAMOND_ERC165_IDS) {
      out.push(`mstore(0x00, ${id}00000000000000000000000000000000000000000000000000000000)`);
      out.push(`mstore(0x20, ${siSlot})`);
      out.push(`sstore(keccak256(0x00, 0x40), 1)`);
    }
  }

  /** Lower diamondInitSolidstate(owner): the @diamond('solidstate') ctor primitive (byte-identical to a
   *  solc solidstate v0.0.61 SolidStateDiamond constructor's owner + ERC-165 registration). Sets owner in
   *  the Ownable namespace (_contractOwner), emits OwnershipTransferred(address(0), owner) (both args
   *  indexed -> log3, no data), then registers solidstate's FIVE supported interface ids in the ERC165Base
   *  namespace (_supportedInterfaces): IDiamondFallback, IERC2535DiamondCut, IERC2535DiamondLoupe, IERC165,
   *  IERC173. (solidstate's constructor pre-registers the diamond's own selectors into the selector storage
   *  too, but JETH routes its own selectors via the dispatch switch; the loupe/routing observable output is
   *  identical, and the test asserts byte-identity against a solc mirror built on the SAME routing model.) */
  private lowerDiamondInitSolidstate(e: Expr & { kind: 'diamondInitSolidstate' }, ctx: LowerCtx, out: string[]): void {
    const MASK = '0xffffffffffffffffffffffffffffffffffffffff';
    const owner = this.fresh();
    out.push(`let ${owner} := and(${this.lowerExpr(e.owner, ctx, out)}, ${MASK})`);
    out.push(`sstore(${String(this.diamondSlot('_contractOwner'))}, ${owner})`);
    // emit OwnershipTransferred(address(0) indexed, owner indexed): both args indexed -> log3, no data.
    out.push(`log3(0, 0, ${OWNERSHIP_TRANSFERRED_TOPIC}, 0, ${owner})`);
    // supportedInterfaces[id] = true: mapping(bytes4=>bool) at the ERC165Base-namespace field slot.
    const siSlot = String(this.diamondSlot('_supportedInterfaces'));
    for (const id of SOLIDSTATE_ERC165_IDS) {
      out.push(`mstore(0x00, ${id}00000000000000000000000000000000000000000000000000000000)`);
      out.push(`mstore(0x20, ${siSlot})`);
      out.push(`sstore(keccak256(0x00, 0x40), 1)`);
    }
  }

  /** Lower __diamondDelegateInit(_init, _calldata): the initializeDiamondCut _init delegatecall, byte-
   *  identical to mudgen's LibDiamondCut.initializeDiamondCut: if _init==0 return (no-op); require
   *  extcodesize(_init)>0 (else a clean revert - the mudgen NoBytecodeAtAddress custom error is the
   *  degenerate path); delegatecall(gas(), _init, _calldata) and on failure bubble the returndata
   *  verbatim (the InitializationFunctionReverted empty-revert path is degenerate). */
  private lowerDiamondDelegateInit(e: Expr & { kind: 'diamondDelegateInit' }, ctx: LowerCtx, out: string[]): void {
    const MASK = '0xffffffffffffffffffffffffffffffffffffffff';
    const init = this.fresh();
    out.push(`let ${init} := and(${this.lowerExpr(e.init, ctx, out)}, ${MASK})`);
    // if _init != address(0): require code, delegatecall _calldata, bubble the revert. (init==0 -> no-op.)
    out.push(`if ${init} {`);
    out.push(`  if iszero(extcodesize(${init})) { revert(0, 0) }`);
    const { mp, len } = this.toMemory(this.lowerDynamic(e.data, ctx, out), out);
    const ok = this.fresh();
    out.push(`  let ${ok} := delegatecall(gas(), ${init}, add(${mp}, 0x20), ${len}, 0, 0)`);
    out.push(`  returndatacopy(0, 0, returndatasize())`);
    out.push(`  if iszero(${ok}) { revert(0, returndatasize()) }`);
    out.push(`}`);
  }

  /** Phase 3 DIAMOND: lower the facets() loupe (`return __diamondFacets()`). Builds the ABI return blob
   *  for `Facet[]` (Facet = {address facetAddress; bytes4[] functionSelectors}) directly from the split
   *  diamond-3 storage in raw Yul, byte-identical to a solc loupe that reads facetAddresses[] then each
   *  facet's functionSelectors[]. JETH has no Facet[] memory local, so this is hand-encoded.
   *
   *  Storage: _facetAddresses is address[] at slot FA (len = sload(FA), data at keccak256(FA));
   *  _facetSelectors is mapping(address=>{bytes4[] sels; uint pos}) at slot FS - facet f's struct is at
   *  keccak256(f . FS), the sels field is field 0 so its bytes4[] len = sload(structSlot), data at
   *  keccak256(structSlot). Each bytes4 element occupies one word LEFT-aligned (solc bytesN packing).
   *
   *  ABI layout of the single dynamic return value Facet[]:
   *    word0: 0x20 (offset to the array)
   *    array: [len] then len head-offset words (each -> a Facet tuple), then the Facet tuples.
   *    Facet tuple (dynamic): head [facetAddress][offset=0x40], tail = bytes4[] ([len][elements]).
   *  All offsets are relative to the array start (the array's own [len] word) for the head table, and to
   *  the tuple start for the tuple's inner offset - matching solc's nested dynamic ABI v2 encoding. */
  private lowerDiamondFacetsReturn(out: string[]): void {
    const FA = String(this.diamondSlot('_facetAddresses'));
    const FS = String(this.diamondSlot('_facetSelectors'));
    const L = (s: string) => out.push(s);
    L('// facets() -> Facet[] : build the ABI return blob from the split diamond-3 storage');
    L(`let _faLen := sload(${FA})`);
    // The free pointer is the return-blob base. word0 = 0x20 (offset to the array).
    L('let _ret := mload(0x40)');
    L('mstore(_ret, 0x20)');
    L('let _arr := add(_ret, 0x20)'); // the array start ([len] word lives here)
    L('mstore(_arr, _faLen)');
    L('let _head := add(_arr, 0x20)'); // the head offset-table (one word per facet)
    // The first tuple sits right after the head table: _faLen words of head.
    L('let _cursor := add(_head, mul(_faLen, 0x20))');
    // data slot of _facetAddresses[]: keccak256(FA)
    L(`mstore(0x00, ${FA})`);
    L('let _faData := keccak256(0x00, 0x20)');
    L('let _i := 0');
    L('for { } lt(_i, _faLen) { _i := add(_i, 1) } {');
    // facet address = _facetAddresses[_i]
    L('  let _facet := and(sload(add(_faData, _i)), 0xffffffffffffffffffffffffffffffffffffffff)');
    // head[_i] = offset of this tuple relative to the HEAD table start (i.e. after the array [len] word),
    // matching solc's array-of-dynamic-tuple ABI v2 encoding.
    L('  mstore(add(_head, mul(_i, 0x20)), sub(_cursor, _head))');
    // tuple head: [facetAddress][offset 0x40 to the bytes4[] tail]
    L('  mstore(_cursor, _facet)');
    L('  mstore(add(_cursor, 0x20), 0x40)');
    // locate the facet's struct slot: keccak256(facet . FS); sels field is field 0 (struct slot itself)
    L('  mstore(0x00, _facet)');
    L(`  mstore(0x20, ${FS})`);
    L('  let _structSlot := keccak256(0x00, 0x40)');
    L('  let _selLen := sload(_structSlot)');
    // bytes4[] tail at _cursor+0x40: [len][elements]
    L('  mstore(add(_cursor, 0x40), _selLen)');
    // data slot of the bytes4[]: keccak256(_structSlot)
    L('  mstore(0x00, _structSlot)');
    L('  let _selData := keccak256(0x00, 0x20)');
    L('  let _selBase := add(_cursor, 0x60)'); // first element word
    L('  let _j := 0');
    L('  for { } lt(_j, _selLen) { _j := add(_j, 1) } {');
    // bytes4[] packs 8 elements per slot (4 bytes each). solc stores element k at byte offset (k%8)*4 from
    // the slot's LOW end: value = (sload(slot) >> ((k%8)*32)) & 0xffffffff, then shl(224) to LEFT-align the
    // bytes4 in its ABI word. Matches JETH's own bytes4[]-element read (the working facetFunctionSelectors).
    L('    let _slot := sload(add(_selData, div(_j, 8)))');
    L('    let _shift := mul(mod(_j, 8), 32)');
    L('    let _elem := shl(224, and(shr(_shift, _slot), 0xffffffff))');
    L('    mstore(add(_selBase, mul(_j, 0x20)), _elem)');
    L('  }');
    // advance the cursor past this tuple: head (0x40) + bytes4[] (0x20 len + selLen words)
    L('  _cursor := add(_cursor, add(0x60, mul(_selLen, 0x20)))');
    L('}');
    L('return(_ret, sub(_cursor, _ret))');
  }

  // ---- Phase 3 DIAMOND (packed / diamond-2 layout) ----------------------------------------------
  // Storage (raw keccak base, the same as the array model):
  //   _facets         (base+0): mapping(bytes4=>bytes32). value = bytes20(facet) | bytes32(uint16 position).
  //   _selectorSlots  (base+1): mapping(uint256=>bytes32). slotIndex (count>>3) -> 8 packed bytes4 selectors,
  //                             selector k at MSB bit position (k&7)<<5: stored bytes32(sel) >> pos.
  //   _selectorCount  (base+2): uint16 total installed selectors (right-aligned alone in its slot).
  // CLEAR_ADDRESS_MASK  = 0xffffffffffffffffffffffff  (low 12 bytes set: keep position, clear addr).
  // CLEAR_SELECTOR_MASK = 0xffffffff << 224           (top 4 bytes set).

  /** Lower __diamondCutPacked(): the entire diamond-2 add/replace/remove loop, byte-identical to mudgen's
   *  LibDiamond.diamondCut + addReplaceRemoveFacetSelectors. Reads _diamondCut (FacetCut[]) directly from
   *  calldata (the diamondCut(...) args region at offset 4). selectorCount + the in-memory selectorSlot are
   *  threaded through; the partially-filled last slot is preloaded before the loop and flushed after. */
  private lowerDiamondCutPacked(out: string[]): void {
    const FACETS = String(this.diamondSlot('_facets'));
    const SLOTS = String(this.diamondSlot('_selectorSlots'));
    const COUNT = String(this.diamondSlot('_selectorCount'));
    const ADDR = '0xffffffffffffffffffffffffffffffffffffffff';
    const CLEAR_ADDR = '0xffffffffffffffffffffffff'; // low 12 bytes set
    const CLEAR_SEL = '0xffffffff00000000000000000000000000000000000000000000000000000000'; // top 4 bytes set
    const L = (s: string) => out.push(s);
    // mapping element slot helper: keccak(key . mapBaseSlot) with key in word 0 (left-aligned bytes4 or the
    // uint256 slotIndex), mapBaseSlot in word 1. We inline mstore pairs at scratch 0x00/0x20.

    L('// diamondCut (packed / diamond-2): read _diamondCut[] from calldata, apply add/replace/remove');
    // The diamondCut args region starts at calldata offset 4. Head: [off _diamondCut][_init][off _calldata].
    // _diamondCut is a dynamic FacetCut[]; its data starts at 4 + head[0].
    L('let _argBase := 4');
    L('let _cutArr := add(_argBase, calldataload(_argBase))'); // points at the array [len] word
    L('let _cutLen := calldataload(_cutArr)');
    L('let _cutElems := add(_cutArr, 0x20)'); // the per-element offset table (each rel to _cutElems)
    // originalSelectorCount + preload the partially-filled last slot.
    L(`let _selectorCount := and(sload(${COUNT}), 0xffff)`);
    L('let _originalCount := _selectorCount');
    L('let _selectorSlot := 0');
    L('if gt(and(_selectorCount, 7), 0) {');
    L(`  mstore(0x00, shr(3, _selectorCount))`);
    L(`  mstore(0x20, ${SLOTS})`);
    L('  _selectorSlot := sload(keccak256(0x00, 0x40))');
    L('}');
    L('let _ci := 0');
    L('for { } lt(_ci, _cutLen) { _ci := add(_ci, 1) } {');
    // FacetCut tuple ptr (dynamic element): _cutElems + offsetTable[_ci]
    L('  let _cut := add(_cutElems, calldataload(add(_cutElems, mul(_ci, 0x20))))');
    L(`  let _facetAddr := and(calldataload(_cut), ${ADDR})`); // field 0: address
    L('  let _action := calldataload(add(_cut, 0x20))'); // field 1: uint8 action
    // field 2: bytes4[] functionSelectors -> offset (rel to _cut) at word 2; [len] then elements
    L('  let _selsPtr := add(_cut, calldataload(add(_cut, 0x40)))');
    L('  let _selsLen := calldataload(_selsPtr)');
    L('  let _selsData := add(_selsPtr, 0x20)'); // first selector word (left-aligned bytes4)
    // require(_selectors.length > 0) - shared across all actions (mudgen runs it BEFORE the action switch).
    L('  if iszero(_selsLen) {');
    for (const l of this.lowerErrorString(new TextEncoder().encode('LibDiamondCut: No selectors in facet to cut')))
      L('    ' + l);
    L('  }');
    L('  switch _action');
    // ---- ADD (action 0) ----
    L('  case 0 {');
    // enforceHasContractCode(facet, "LibDiamondCut: Add facet has no code") - the ONLY pre-loop check (no
    // address(0) guard: extcodesize(0)==0 so a zero facet reverts here too).
    L('    if iszero(extcodesize(_facetAddr)) {');
    for (const l of this.lowerErrorString(new TextEncoder().encode('LibDiamondCut: Add facet has no code')))
      L('      ' + l);
    L('    }');
    L('    let _si := 0');
    L('    for { } lt(_si, _selsLen) { _si := add(_si, 1) } {');
    L('      let _sel := and(calldataload(add(_selsData, mul(_si, 0x20))), 0xffffffff00000000000000000000000000000000000000000000000000000000)');
    // bytes32 oldFacet = ds.facets[selector]; require(address(bytes20(oldFacet)) == address(0))
    L(`      mstore(0x00, _sel)`);
    L(`      mstore(0x20, ${FACETS})`);
    L('      let _fSlot := keccak256(0x00, 0x40)');
    L('      let _oldVal := sload(_fSlot)');
    L('      if shr(96, _oldVal) {');
    for (const l of this.lowerErrorString(
      new TextEncoder().encode("LibDiamondCut: Can't add function that already exists"),
    ))
      L('        ' + l);
    L('      }');
    // facets[sel] = bytes20(facet) | bytes32(selectorCount): address high 20 bytes (shl 96), count in low.
    L('      sstore(_fSlot, or(shl(96, _facetAddr), _selectorCount))');
    // pack the selector into the working slot: pos = (count & 7) << 5
    L('      let _pos := shl(5, and(_selectorCount, 7))');
    L(`      _selectorSlot := or(and(_selectorSlot, not(shr(_pos, ${CLEAR_SEL}))), shr(_pos, _sel))`);
    // if pos == 224 (8th selector) flush selectorSlots[count>>3] = slot, reset slot.
    L('      if eq(_pos, 224) {');
    L(`        mstore(0x00, shr(3, _selectorCount))`);
    L(`        mstore(0x20, ${SLOTS})`);
    L('        sstore(keccak256(0x00, 0x40), _selectorSlot)');
    L('        _selectorSlot := 0');
    L('      }');
    L('      _selectorCount := add(_selectorCount, 1)');
    L('    }');
    L('  }');
    // ---- REPLACE (action 1) ----
    L('  case 1 {');
    // enforceHasContractCode(facet, "LibDiamondCut: Replace facet has no code")
    L('    if iszero(extcodesize(_facetAddr)) {');
    for (const l of this.lowerErrorString(new TextEncoder().encode('LibDiamondCut: Replace facet has no code')))
      L('      ' + l);
    L('    }');
    L('    let _si := 0');
    L('    for { } lt(_si, _selsLen) { _si := add(_si, 1) } {');
    L('      let _sel := and(calldataload(add(_selsData, mul(_si, 0x20))), 0xffffffff00000000000000000000000000000000000000000000000000000000)');
    L(`      mstore(0x00, _sel)`);
    L(`      mstore(0x20, ${FACETS})`);
    L('      let _fSlot := keccak256(0x00, 0x40)');
    L('      let _oldVal := sload(_fSlot)');
    L('      let _oldFacet := shr(96, _oldVal)');
    // mudgen REPLACE require order: immutable, then same-function, then doesn't-exist.
    L('      if eq(_oldFacet, address()) {');
    for (const l of this.lowerErrorString(new TextEncoder().encode("LibDiamondCut: Can't replace immutable function")))
      L('        ' + l);
    L('      }');
    L('      if eq(_oldFacet, _facetAddr) {');
    for (const l of this.lowerErrorString(
      new TextEncoder().encode("LibDiamondCut: Can't replace function with same function"),
    ))
      L('        ' + l);
    L('      }');
    L('      if iszero(_oldFacet) {');
    for (const l of this.lowerErrorString(
      new TextEncoder().encode("LibDiamondCut: Can't replace function that doesn't exist"),
    ))
      L('        ' + l);
    L('      }');
    // facets[sel] = (oldVal & CLEAR_ADDRESS_MASK) | bytes20(facet): keep low position, swap high address.
    L(`      sstore(_fSlot, or(and(_oldVal, ${CLEAR_ADDR}), shl(96, _facetAddr)))`);
    L('    }');
    L('  }');
    // ---- REMOVE (action 2) ----
    L('  case 2 {');
    // require(_newFacetAddress == address(0))
    L('    if _facetAddr {');
    for (const l of this.lowerErrorString(new TextEncoder().encode('LibDiamondCut: Remove facet address must be address(0)')))
      L('      ' + l);
    L('    }');
    L('    let _selectorSlotCount := shr(3, _selectorCount)');
    L('    let _selectorInSlotIndex := and(_selectorCount, 7)');
    L('    let _si := 0');
    L('    for { } lt(_si, _selsLen) { _si := add(_si, 1) } {');
    // step the cursor back
    L('      switch _selectorInSlotIndex');
    L('      case 0 {');
    L('        _selectorSlotCount := sub(_selectorSlotCount, 1)');
    L(`        mstore(0x00, _selectorSlotCount)`);
    L(`        mstore(0x20, ${SLOTS})`);
    L('        _selectorSlot := sload(keccak256(0x00, 0x40))');
    L('        _selectorInSlotIndex := 7');
    L('      }');
    L('      default { _selectorInSlotIndex := sub(_selectorInSlotIndex, 1) }');
    L('      let _sel := and(calldataload(add(_selsData, mul(_si, 0x20))), 0xffffffff00000000000000000000000000000000000000000000000000000000)');
    // read the removed selector's facets record
    L(`      mstore(0x00, _sel)`);
    L(`      mstore(0x20, ${FACETS})`);
    L('      let _fSlot := keccak256(0x00, 0x40)');
    L('      let _oldVal := sload(_fSlot)');
    L('      let _oldFacet := shr(96, _oldVal)');
    L('      if iszero(_oldFacet) {');
    for (const l of this.lowerErrorString(
      new TextEncoder().encode("LibDiamondCut: Can't remove function that doesn't exist"),
    ))
      L('        ' + l);
    L('      }');
    L('      if eq(_oldFacet, address()) {');
    for (const l of this.lowerErrorString(new TextEncoder().encode("LibDiamondCut: Can't remove immutable function")))
      L('        ' + l);
    L('      }');
    // lastSelector = bytes4(selectorSlot << (selectorInSlotIndex << 5)) (left-aligned)
    L('      let _lastSelector := and(shl(shl(5, _selectorInSlotIndex), _selectorSlot), 0xffffffff00000000000000000000000000000000000000000000000000000000)');
    // if lastSelector != sel: move the last selector record over the removed one
    L('      if iszero(eq(_lastSelector, _sel)) {');
    // facets[lastSelector] = (oldVal & CLEAR_ADDRESS_MASK) | bytes20(facets[lastSelector])
    L(`        mstore(0x00, _lastSelector)`);
    L(`        mstore(0x20, ${FACETS})`);
    L('        let _lastSlot := keccak256(0x00, 0x40)');
    L(`        sstore(_lastSlot, or(and(_oldVal, ${CLEAR_ADDR}), and(sload(_lastSlot), shl(96, ${ADDR}))))`);
    L('      }');
    // delete facets[sel]
    L('      sstore(_fSlot, 0)');
    // recover the removed selector's old position from the LOW bytes of oldVal (uint16)
    L('      let _oldSelectorCount := and(_oldVal, 0xffff)');
    L('      let _oldSelectorsSlotCount := shr(3, _oldSelectorCount)');
    L('      let _oldSelectorInSlotPosition := shl(5, and(_oldSelectorCount, 7))');
    // write lastSelector into that gap
    L('      switch eq(_oldSelectorsSlotCount, _selectorSlotCount)');
    L('      case 0 {'); // gap is in a different (already-stored) slot
    L(`        mstore(0x00, _oldSelectorsSlotCount)`);
    L(`        mstore(0x20, ${SLOTS})`);
    L('        let _gapSlotKey := keccak256(0x00, 0x40)');
    L('        let _oldSlotVal := sload(_gapSlotKey)');
    L(`        _oldSlotVal := or(and(_oldSlotVal, not(shr(_oldSelectorInSlotPosition, ${CLEAR_SEL}))), shr(_oldSelectorInSlotPosition, _lastSelector))`);
    L('        sstore(_gapSlotKey, _oldSlotVal)');
    L('      }');
    L('      default {'); // gap is in the in-memory working slot
    L(`        _selectorSlot := or(and(_selectorSlot, not(shr(_oldSelectorInSlotPosition, ${CLEAR_SEL}))), shr(_oldSelectorInSlotPosition, _lastSelector))`);
    L('      }');
    // if the trailing slot is now empty, delete it and reset the working slot
    L('      if iszero(_selectorInSlotIndex) {');
    L(`        mstore(0x00, _selectorSlotCount)`);
    L(`        mstore(0x20, ${SLOTS})`);
    L('        sstore(keccak256(0x00, 0x40), 0)');
    L('        _selectorSlot := 0');
    L('      }');
    L('    }');
    L('    _selectorCount := add(mul(_selectorSlotCount, 8), _selectorInSlotIndex)');
    L('  }');
    // ---- default: invalid action ----
    L('  default {');
    for (const l of this.lowerErrorString(new TextEncoder().encode('LibDiamondCut: Incorrect FacetCutAction')))
      L('    ' + l);
    L('  }');
    L('}');
    // after the loop: write selectorCount if changed; flush the partially-filled last slot.
    L('if iszero(eq(_selectorCount, _originalCount)) {');
    L(`  sstore(${COUNT}, _selectorCount)`);
    L('}');
    L('if gt(and(_selectorCount, 7), 0) {');
    L(`  mstore(0x00, shr(3, _selectorCount))`);
    L(`  mstore(0x20, ${SLOTS})`);
    L('  sstore(keccak256(0x00, 0x40), _selectorSlot)');
    L('}');
  }

  /** Lower __diamondCutSolidstate(): the solidstate v0.0.61 _diamondCut + _add/_replace/_removeFacetSelectors.
   *  The selector PACKING is identical to the packed/diamond-2 model (facet in the HIGH 20 bytes | uint16
   *  global index in the LOW bytes of selectorInfo[sel]; 8 selectors per 32-byte slug, selector k at bit
   *  position (k&7)<<5 from the MSB). The DIFFERENCES from the mudgen packed cut, all reproduced byte-exactly:
   *    - the revert set is solidstate's custom errors (DiamondWritable__*) instead of mudgen's strings;
   *    - ADD allows target == address(this) (an "immutable" self-route) and otherwise requires code;
   *    - REPLACE's require order is not-found, immutable, target-identical;
   *    - REMOVE decrements the count first, then swaps the trailing selector into the freed gap.
   *  Reads _diamondCut (FacetCut[]) directly from calldata (the diamondCut(...) args region at offset 4),
   *  matching solc's ABI v2 decode. */
  private lowerDiamondCutSolidstate(out: string[]): void {
    const FACETS = String(this.diamondSlot('_facets')); // selectorInfo
    const SLOTS = String(this.diamondSlot('_selectorSlots')); // selectorSlugs
    const COUNT = String(this.diamondSlot('_selectorCount'));
    const ADDR = '0xffffffffffffffffffffffffffffffffffffffff';
    const CLEAR_ADDR = '0xffffffffffffffffffffffff'; // CLEAR_ADDRESS_MASK: low 12 bytes set
    const CLEAR_SEL = '0xffffffff00000000000000000000000000000000000000000000000000000000'; // CLEAR_SELECTOR_MASK
    const SELMASK = '0xffffffff00000000000000000000000000000000000000000000000000000000';
    const L = (s: string) => out.push(s);
    // bare custom-error revert: mstore(0, shl(224, selector)); revert(0, 4).
    const rev = (sel: string, indent: string) => {
      L(`${indent}mstore(0x00, shl(224, ${sel}))`);
      L(`${indent}revert(0x00, 0x04)`);
    };
    L('// diamondCut (solidstate v0.0.61): read _diamondCut[] from calldata, apply add/replace/remove');
    L('let _argBase := 4');
    L('let _cutArr := add(_argBase, calldataload(_argBase))');
    L('let _cutLen := calldataload(_cutArr)');
    L('let _cutElems := add(_cutArr, 0x20)');
    L(`let _selectorCount := and(sload(${COUNT}), 0xffff)`);
    L('let _originalCount := _selectorCount');
    L('let _slug := 0');
    // if selectorCount & 7 != 0: preload the partially-filled last slug.
    L('if gt(and(_selectorCount, 7), 0) {');
    L(`  mstore(0x00, shr(3, _selectorCount))`);
    L(`  mstore(0x20, ${SLOTS})`);
    L('  _slug := sload(keccak256(0x00, 0x40))');
    L('}');
    L('let _ci := 0');
    L('for { } lt(_ci, _cutLen) { _ci := add(_ci, 1) } {');
    L('  let _cut := add(_cutElems, calldataload(add(_cutElems, mul(_ci, 0x20))))');
    L(`  let _facetAddr := and(calldataload(_cut), ${ADDR})`); // FacetCut.target
    L('  let _action := calldataload(add(_cut, 0x20))'); // FacetCut.action
    L('  let _selsPtr := add(_cut, calldataload(add(_cut, 0x40)))'); // FacetCut.selectors
    L('  let _selsLen := calldataload(_selsPtr)');
    L('  let _selsData := add(_selsPtr, 0x20)');
    // if (facetCut.selectors.length == 0) revert DiamondWritable__SelectorNotSpecified()
    L('  if iszero(_selsLen) {');
    rev('0xeb6c3aeb', '    ');
    L('  }');
    L('  switch _action');
    // ---- ADD (0) ----
    L('  case 0 {');
    // if (target.isContract()) { if (target == address(this)) revert SelectorIsImmutable; }
    // else if (target != address(this)) revert TargetHasNoCode;
    L('    switch iszero(extcodesize(_facetAddr))');
    L('    case 0 {'); // target has code
    L('      if eq(_facetAddr, address()) {');
    rev('0xe9835731', '        '); // SelectorIsImmutable
    L('      }');
    L('    }');
    L('    default {'); // target has no code
    L('      if iszero(eq(_facetAddr, address())) {');
    rev('0xf77172ac', '        '); // TargetHasNoCode
    L('      }');
    L('    }');
    L('    let _si := 0');
    L('    for { } lt(_si, _selsLen) { _si := add(_si, 1) } {');
    L(`      let _sel := and(calldataload(add(_selsData, mul(_si, 0x20))), ${SELMASK})`);
    L(`      mstore(0x00, _sel)`);
    L(`      mstore(0x20, ${FACETS})`);
    L('      let _fSlot := keccak256(0x00, 0x40)');
    // if (selectorInfo[sel] != bytes32(0)) revert SelectorAlreadyAdded
    L('      if sload(_fSlot) {');
    rev('0x92474ee2', '        '); // SelectorAlreadyAdded
    L('      }');
    // selectorInfo[sel] = bytes32(selectorCount) | bytes20(target)
    L('      sstore(_fSlot, or(shl(96, _facetAddr), _selectorCount))');
    // pos = (selectorCount & 7) << 5; slug = (slug & ~(CLEAR_SEL >> pos)) | (sel >> pos)
    L('      let _pos := shl(5, and(_selectorCount, 7))');
    L(`      _slug := or(and(_slug, not(shr(_pos, ${CLEAR_SEL}))), shr(_pos, _sel))`);
    // if (pos == 224) selectorSlugs[selectorCount >> 3] = slug
    L('      if eq(_pos, 224) {');
    L(`        mstore(0x00, shr(3, _selectorCount))`);
    L(`        mstore(0x20, ${SLOTS})`);
    L('        sstore(keccak256(0x00, 0x40), _slug)');
    L('      }');
    L('      _selectorCount := add(_selectorCount, 1)');
    L('    }');
    L('  }');
    // ---- REPLACE (1) ----
    L('  case 1 {');
    // if (!target.isContract()) revert TargetHasNoCode
    L('    if iszero(extcodesize(_facetAddr)) {');
    rev('0xf77172ac', '      ');
    L('    }');
    L('    let _si := 0');
    L('    for { } lt(_si, _selsLen) { _si := add(_si, 1) } {');
    L(`      let _sel := and(calldataload(add(_selsData, mul(_si, 0x20))), ${SELMASK})`);
    L(`      mstore(0x00, _sel)`);
    L(`      mstore(0x20, ${FACETS})`);
    L('      let _fSlot := keccak256(0x00, 0x40)');
    L('      let _selectorInfo := sload(_fSlot)');
    L('      let _oldFacet := shr(96, _selectorInfo)');
    // solidstate order: not-found, immutable, identical
    L('      if iszero(_oldFacet) {');
    rev('0x6fc4b52e', '        '); // SelectorNotFound
    L('      }');
    L('      if eq(_oldFacet, address()) {');
    rev('0xe9835731', '        '); // SelectorIsImmutable
    L('      }');
    L('      if eq(_oldFacet, _facetAddr) {');
    rev('0x617557e6', '        '); // ReplaceTargetIsIdentical
    L('      }');
    // selectorInfo[sel] = (selectorInfo & CLEAR_ADDRESS_MASK) | bytes20(target)
    L(`      sstore(_fSlot, or(and(_selectorInfo, ${CLEAR_ADDR}), shl(96, _facetAddr)))`);
    L('    }');
    L('  }');
    // ---- REMOVE (2) ----
    L('  case 2 {');
    // if (target != address(0)) revert RemoveTargetNotZeroAddress
    L('    if _facetAddr {');
    rev('0xeacd2424', '      ');
    L('    }');
    L('    let _si := 0');
    L('    for { } lt(_si, _selsLen) { _si := add(_si, 1) } {');
    L('      _selectorCount := sub(_selectorCount, 1)');
    L(`      let _sel := and(calldataload(add(_selsData, mul(_si, 0x20))), ${SELMASK})`);
    L(`      mstore(0x00, _sel)`);
    L(`      mstore(0x20, ${FACETS})`);
    L('      let _fSlot := keccak256(0x00, 0x40)');
    L('      let _selectorInfo := sload(_fSlot)');
    L('      sstore(_fSlot, 0)'); // delete selectorInfo[sel]
    L('      let _oldFacet := shr(96, _selectorInfo)');
    L('      if iszero(_oldFacet) {');
    rev('0x6fc4b52e', '        '); // SelectorNotFound
    L('      }');
    L('      if eq(_oldFacet, address()) {');
    rev('0xe9835731', '        '); // SelectorIsImmutable
    L('      }');
    // if (selectorCount & 7 == 7) lastSlug = selectorSlugs[selectorCount >> 3]
    L('      if eq(and(_selectorCount, 7), 7) {');
    L(`        mstore(0x00, shr(3, _selectorCount))`);
    L(`        mstore(0x20, ${SLOTS})`);
    L('        _slug := sload(keccak256(0x00, 0x40))');
    L('      }');
    // lastSelector = bytes4(lastSlug << ((selectorCount & 7) << 5))
    L(`      let _lastSelector := and(shl(shl(5, and(_selectorCount, 7)), _slug), ${SELMASK})`);
    // if (lastSelector != selector) selectorInfo[lastSelector] = (selectorInfo & CLEAR_ADDRESS_MASK) | bytes20(selectorInfo[lastSelector])
    L('      if iszero(eq(_lastSelector, _sel)) {');
    L(`        mstore(0x00, _lastSelector)`);
    L(`        mstore(0x20, ${FACETS})`);
    L('        let _lastSlot := keccak256(0x00, 0x40)');
    L(`        sstore(_lastSlot, or(and(_selectorInfo, ${CLEAR_ADDR}), and(sload(_lastSlot), shl(96, ${ADDR}))))`);
    L('      }');
    // slugIndex = uint16(selectorInfo) >> 3; pos = (uint16(selectorInfo) & 7) << 5
    L('      let _slugIndex := shr(3, and(_selectorInfo, 0xffff))');
    L('      let _posInSlug := shl(5, and(and(_selectorInfo, 0xffff), 7))');
    // if (slugIndex == selectorCount >> 3) lastSlug = insert(lastSlug, lastSelector, pos)
    // else selectorSlugs[slugIndex] = insert(selectorSlugs[slugIndex], lastSelector, pos)
    L('      switch eq(_slugIndex, shr(3, _selectorCount))');
    L('      case 1 {');
    L(`        _slug := or(and(_slug, not(shr(_posInSlug, ${CLEAR_SEL}))), shr(_posInSlug, _lastSelector))`);
    L('      }');
    L('      default {');
    L(`        mstore(0x00, _slugIndex)`);
    L(`        mstore(0x20, ${SLOTS})`);
    L('        let _gapKey := keccak256(0x00, 0x40)');
    L(`        sstore(_gapKey, or(and(sload(_gapKey), not(shr(_posInSlug, ${CLEAR_SEL}))), shr(_posInSlug, _lastSelector)))`);
    L('      }');
    L('    }');
    L('  }');
    L('}');
    // if (selectorCount != originalSelectorCount) $.selectorCount = uint16(selectorCount)
    L('if iszero(eq(_selectorCount, _originalCount)) {');
    L(`  sstore(${COUNT}, and(_selectorCount, 0xffff))`);
    L('}');
    // if (selectorCount & 7 != 0) selectorSlugs[selectorCount >> 3] = slug
    L('if gt(and(_selectorCount, 7), 0) {');
    L(`  mstore(0x00, shr(3, _selectorCount))`);
    L(`  mstore(0x20, ${SLOTS})`);
    L('  sstore(keccak256(0x00, 0x40), _slug)');
    L('}');
  }

  /** The common diamond-2 loupe scan, emitted into `out`: iterates the packed selectorSlots in order and,
   *  for each installed selector, sets `_sel` (left-aligned bytes4) and `_fa` (facet address) and runs the
   *  caller-supplied body lines. Uses fresh locals prefixed `_lp`. The body sees `_sel`, `_fa`, `_idx`
   *  (0-based selector index). Mirrors mudgen's `for slotIndex { slot=selectorSlots[slotIndex]; for j 0..7 }`. */
  private emitPackedLoupeScan(out: string[], body: string[]): void {
    const SLOTS = String(this.diamondSlot('_selectorSlots'));
    const FACETS = String(this.diamondSlot('_facets'));
    const COUNT = String(this.diamondSlot('_selectorCount'));
    const ADDR = '0xffffffffffffffffffffffffffffffffffffffff';
    const L = (s: string) => out.push(s);
    L(`let _lpCount := and(sload(${COUNT}), 0xffff)`);
    L('let _idx := 0'); // 0-based global selector index
    L('let _slotIndex := 0');
    L('for { } lt(_idx, _lpCount) { _slotIndex := add(_slotIndex, 1) } {');
    L(`  mstore(0x00, _slotIndex)`);
    L(`  mstore(0x20, ${SLOTS})`);
    L('  let _slot := sload(keccak256(0x00, 0x40))');
    L('  let _j := 0');
    L('  for { } and(lt(_j, 8), lt(_idx, _lpCount)) { _j := add(_j, 1) } {');
    L('    let _sel := and(shl(shl(5, _j), _slot), 0xffffffff00000000000000000000000000000000000000000000000000000000)');
    L(`    mstore(0x00, _sel)`);
    L(`    mstore(0x20, ${FACETS})`);
    L(`    let _fa := and(shr(96, sload(keccak256(0x00, 0x40))), ${ADDR})`);
    for (const b of body) L('    ' + b);
    L('    _idx := add(_idx, 1)');
    L('  }');
    L('}');
  }

  /** facets() -> Facet[] (diamond-2 reconstruct). Over-allocate Facet[](selectorCount) + per-facet selector
   *  arrays at selectorCount each, linear-search-dedupe facet addresses while scanning the packed slots,
   *  then build the ABI return blob with the REAL (shrunk) lengths. First-seen facet order; selectors in
   *  scan order. Byte-identical to mudgen's DiamondLoupeFacet.facets() (the mstore-shrink result). */
  private lowerDiamondFacetsReturnPacked(out: string[]): void {
    const L = (s: string) => out.push(s);
    const COUNT = String(this.diamondSlot('_selectorCount'));
    L('// facets() packed: reconstruct facet grouping in memory, then ABI-encode Facet[]');
    L(`let _n := and(sload(${COUNT}), 0xffff)`);
    // Scratch tables in memory (above the return blob region). We use the free pointer as a work arena:
    //   _addrs : address[_n]   (distinct facet addresses, first-seen order)        -> _work + 0
    //   _counts: uint[_n]      (selector count per distinct facet)                  -> _work + _n*0x20
    //   _sels  : bytes4[_n*_n] (selectors per facet, row-major: facet f row at f*_n) -> _work + 2*_n*0x20
    L('let _work := mload(0x40)');
    L('let _addrs := _work');
    L('let _counts := add(_work, mul(_n, 0x20))');
    L('let _sels := add(_work, mul(_n, 0x40))');
    L('let _numFacets := 0');
    // scan
    const body: string[] = [];
    body.push('let _fi := 0');
    body.push('let _found := 0');
    body.push('for { } lt(_fi, _numFacets) { _fi := add(_fi, 1) } {');
    body.push('  if eq(mload(add(_addrs, mul(_fi, 0x20))), _fa) { _found := 1 break }');
    body.push('}');
    body.push('if iszero(_found) {');
    body.push('  mstore(add(_addrs, mul(_numFacets, 0x20)), _fa)');
    body.push('  mstore(add(_counts, mul(_numFacets, 0x20)), 0)');
    body.push('  _fi := _numFacets');
    body.push('  _numFacets := add(_numFacets, 1)');
    body.push('}');
    // append _sel to facet _fi's row at offset (count)
    body.push('let _c := mload(add(_counts, mul(_fi, 0x20)))');
    body.push('mstore(add(_sels, mul(add(mul(_fi, _n), _c), 0x20)), _sel)');
    body.push('mstore(add(_counts, mul(_fi, 0x20)), add(_c, 1))');
    this.emitPackedLoupeScan(out, body);
    // build the ABI return blob AFTER the scratch arena (so we don't clobber it mid-encode).
    L('let _ret := add(_sels, mul(mul(_n, _n), 0x20))');
    L('mstore(_ret, 0x20)'); // offset to the array
    L('let _arr := add(_ret, 0x20)');
    L('mstore(_arr, _numFacets)');
    L('let _head := add(_arr, 0x20)');
    L('let _cursor := add(_head, mul(_numFacets, 0x20))');
    L('let _f := 0');
    L('for { } lt(_f, _numFacets) { _f := add(_f, 1) } {');
    L('  let _fAddr := mload(add(_addrs, mul(_f, 0x20)))');
    L('  let _fCount := mload(add(_counts, mul(_f, 0x20)))');
    L('  mstore(add(_head, mul(_f, 0x20)), sub(_cursor, _head))'); // head[f] rel to head table start
    L('  mstore(_cursor, _fAddr)'); // tuple head: [facetAddress][offset 0x40]
    L('  mstore(add(_cursor, 0x20), 0x40)');
    L('  mstore(add(_cursor, 0x40), _fCount)'); // bytes4[] tail: [len][elements]
    L('  let _selBase := add(_cursor, 0x60)');
    L('  let _k := 0');
    L('  for { } lt(_k, _fCount) { _k := add(_k, 1) } {');
    L('    mstore(add(_selBase, mul(_k, 0x20)), mload(add(_sels, mul(add(mul(_f, _n), _k), 0x20))))');
    L('  }');
    L('  _cursor := add(_cursor, add(0x60, mul(_fCount, 0x20)))');
    L('}');
    L('return(_ret, sub(_cursor, _ret))');
  }

  /** facetFunctionSelectors(facet) -> bytes4[] (diamond-2): scan the packed slots, collect the selectors
   *  whose facet == the argument, in scan order. Byte-identical to mudgen's mstore-shrunk bytes4[]. */
  private lowerDiamondFacetSelectorsReturnPacked(facet: Expr, ctx: LowerCtx, out: string[]): void {
    const ADDR = '0xffffffffffffffffffffffffffffffffffffffff';
    const L = (s: string) => out.push(s);
    L('// facetFunctionSelectors(facet) packed: collect selectors whose facet == arg');
    const fa = this.fresh();
    L(`let ${fa} := and(${this.lowerExpr(facet, ctx, out)}, ${ADDR})`);
    L('let _ret := mload(0x40)');
    L('mstore(_ret, 0x20)'); // offset to the bytes4[]
    L('let _arr := add(_ret, 0x20)'); // [len][elements]
    L('let _data := add(_arr, 0x20)');
    L('let _count := 0');
    const body: string[] = [];
    body.push(`if eq(_fa, ${fa}) {`);
    body.push('  mstore(add(_data, mul(_count, 0x20)), _sel)');
    body.push('  _count := add(_count, 1)');
    body.push('}');
    this.emitPackedLoupeScan(out, body);
    L('mstore(_arr, _count)');
    L('return(_ret, add(0x40, mul(_count, 0x20)))');
  }

  /** facetAddresses() -> address[] (diamond-2): scan the packed slots, dedupe facet addresses (linear
   *  search), first-seen order. Byte-identical to mudgen's mstore-shrunk address[]. */
  private lowerDiamondFacetAddressesReturnPacked(out: string[]): void {
    const L = (s: string) => out.push(s);
    L('// facetAddresses() packed: dedupe facet addresses in first-seen scan order');
    L('let _ret := mload(0x40)');
    L('mstore(_ret, 0x20)');
    L('let _arr := add(_ret, 0x20)');
    L('let _data := add(_arr, 0x20)');
    L('let _count := 0');
    const body: string[] = [];
    body.push('let _fi := 0');
    body.push('let _found := 0');
    body.push('for { } lt(_fi, _count) { _fi := add(_fi, 1) } {');
    body.push('  if eq(mload(add(_data, mul(_fi, 0x20))), _fa) { _found := 1 break }');
    body.push('}');
    body.push('if iszero(_found) {');
    body.push('  mstore(add(_data, mul(_count, 0x20)), _fa)');
    body.push('  _count := add(_count, 1)');
    body.push('}');
    this.emitPackedLoupeScan(out, body);
    L('mstore(_arr, _count)');
    L('return(_ret, add(0x40, mul(_count, 0x20)))');
  }

  /** Phase 2d (beacon proxy): lower proxyInitBeacon(beacon, initData), byte-identical to the OZ BeaconProxy
   *  5.x constructor (ERC1967Utils._setBeacon + the optional init delegatecall): require(isContract(beacon))
   *  -> sstore the EIP-1967 BEACON slot -> emit BeaconUpgraded(indexed beacon) -> if initData.length>0,
   *  STATICCALL beacon.implementation() (0x5c60da1b) for the current impl (revert on a failed/short
   *  staticcall), then delegatecall(impl, initData) and BUBBLE the revert verbatim. */
  private lowerProxyInitBeacon(e: Expr & { kind: 'proxyInitBeacon' }, ctx: LowerCtx, out: string[]): void {
    const MASK = '0xffffffffffffffffffffffffffffffffffffffff';
    const beacon = this.fresh();
    out.push(`let ${beacon} := and(${this.lowerExpr(e.beacon, ctx, out)}, ${MASK})`);
    // require(isContract(beacon)) -> a clean empty revert on a non-contract (degenerate failure path).
    out.push(`if iszero(extcodesize(${beacon})) { revert(0, 0) }`);
    out.push(`sstore(${EIP1967_BEACON_SLOT}, ${beacon})`);
    // emit BeaconUpgraded(address indexed beacon): an indexed-only event, log2 over no data.
    out.push(`log2(0, 0, ${BEACON_UPGRADED_TOPIC}, ${beacon})`);
    // if initData.length>0: fetch the current impl via the beacon's implementation() staticcall, then run
    // initData against it by delegatecall and bubble the callee's revert verbatim. Materialize the data
    // FIRST (at the free ptr), then use scratch word 0 for the staticcall (the data is untouched at the ptr).
    const { mp, len } = this.toMemory(this.lowerDynamic(e.initData, ctx, out), out);
    out.push(`if gt(${len}, 0) {`);
    out.push(`  mstore(0, ${IMPLEMENTATION_SELECTOR}00000000000000000000000000000000000000000000000000000000)`);
    const sok = this.fresh();
    out.push(`  let ${sok} := staticcall(gas(), ${beacon}, 0, 4, 0, 0x20)`);
    out.push(`  if or(iszero(${sok}), lt(returndatasize(), 0x20)) { revert(0, 0) }`);
    const impl = this.fresh();
    out.push(`  let ${impl} := and(mload(0), ${MASK})`);
    const ok = this.fresh();
    out.push(`  let ${ok} := delegatecall(gas(), ${impl}, add(${mp}, 0x20), ${len}, 0, 0)`);
    out.push(`  returndatacopy(0, 0, returndatasize())`);
    out.push(`  if iszero(${ok}) { revert(0, returndatasize()) }`);
    out.push(`}`);
  }

  /** Phase 2b transparent proxy: the admin-branch upgradeToAndCall(address,bytes) handler. Decodes
   *  (newImpl, data) from calldata[4:] and runs the EIP-1967 upgrade sequence shared with upgradeProxy /
   *  ERC1967Utils.upgradeToAndCall: require(isContract(newImpl)) -> sstore impl slot -> emit Upgraded ->
   *  if data.length>0 delegatecall(newImpl, data) and BUBBLE the revert. The caller emits `return(0,0)`
   *  after this so the admin upgrade returns empty returndata (OZ TransparentUpgradeableProxy behaviour).
   *  Returns the lines (caller indents). Reads the data blob from calldata into memory at the free ptr. */
  private emitTransparentAdminUpgrade(): string[] {
    const MASK = '0xffffffffffffffffffffffffffffffffffffffff';
    const out: string[] = [];
    // SECURITY: the args (address newImpl, bytes data) MUST be ABI-validated exactly as solc's external
    // decoder does BEFORE any state change - a malformed word must EMPTY-revert with the impl slot
    // unchanged and NO Upgraded log, matching `abi.decode(msg.data[4:], (address, bytes))`. Solc requires
    // (1) the full 2-word static head present (calldatasize >= 0x44); (2) the address arg's high 96 bits
    // zero (a dirty word EMPTY-reverts); (3) the bytes offset word + its [len][data] tail fully within
    // calldata (routed through the SAME jeth_calldata_dyn validator the standard @external (address,bytes)
    // decoder uses, base = byte 4).
    out.push('if lt(calldatasize(), 0x44) { revert(0, 0) }');
    out.push('if shr(160, calldataload(4)) { revert(0, 0) }');
    // newImpl: the first arg word (at calldata offset 4), masked to 160 bits.
    out.push(`let _newImpl := and(calldataload(4), ${MASK})`);
    // The bytes arg: word at offset 0x24 is its offset relative to the args region (calldata start + 4).
    // solc's TransparentUpgradeableProxy decodes into `bytes memory` (abi.decode(msg.data[4:],
    // (address,bytes))), so use the MEMORY-decoder validator: an oversized length is Panic(0x41), not an
    // empty revert (matches solc's memory materialization). Returns (calldata dataPtr, len).
    out.push('let _dataPtr, _dataLen := ' + this.calldataDynMem() + '(calldataload(0x24))');
    // require(isContract(newImpl)) -> a clean empty revert on a non-contract (degenerate failure path).
    out.push('if iszero(extcodesize(_newImpl)) { revert(0, 0) }');
    out.push(`sstore(${EIP1967_IMPL_SLOT}, _newImpl)`);
    // emit Upgraded(address indexed implementation): indexed-only event, log2 over no data.
    out.push(`log2(0, 0, ${UPGRADED_TOPIC}, _newImpl)`);
    // if data.length>0: copy the validated calldata slice ([_dataPtr, +_dataLen)) into memory, then
    // delegatecall(gas(), newImpl, data) and bubble the callee's revert verbatim.
    out.push('if gt(_dataLen, 0) {');
    out.push('  let _mem := mload(0x40)');
    out.push('  calldatacopy(_mem, _dataPtr, _dataLen)');
    out.push('  let _ok2 := delegatecall(gas(), _newImpl, _mem, _dataLen, 0, 0)');
    out.push('  returndatacopy(0, 0, returndatasize())');
    out.push('  if iszero(_ok2) { revert(0, returndatasize()) }');
    out.push('}');
    return out;
  }

  /** Phase 2c (UUPS): emit the hand-written body of a synthesized `@uups @contract` entry, byte-identical
   *  to OZ UUPSUpgradeable 5.x. Two kinds:
   *   - proxiableUUID(): return the EIP-1967 impl slot constant as a bytes32.
   *   - upgradeToAndCall(address newImpl, bytes data): decode (newImpl, data) from calldata, call the user
   *     gate authorizeUpgrade(newImpl), run the anti-brick proxiableUUID staticcall (revert
   *     ERC1967InvalidImplementation(newImpl) on a failed/short staticcall; UUPSUnsupportedProxiableUUID(slot)
   *     on a returned slot != the EIP-1967 impl slot), then the EIP-1967 upgrade shared with upgradeProxy
   *     (sstore impl slot, emit Upgraded(indexed), data.length>0 -> delegatecall+bubble), return empty. */
  private emitUupsEntry(fn: FunctionIR): string[] {
    const out: string[] = [];
    const MASK = '0xffffffffffffffffffffffffffffffffffffffff';
    if (fn.uupsKind === 'proxiableUUID') {
      // proxiableUUID(): no params; return the EIP-1967 impl slot constant (a bytes32 in word 0).
      out.push(`mstore(0, ${EIP1967_IMPL_SLOT})`);
      out.push('return(0, 0x20)');
      return out;
    }
    // upgradeToAndCall(address newImpl, bytes data): the args mirror the transparent admin upgrade decode
    // (newImpl at calldata 4; the bytes arg's offset word at 0x24 is relative to the args region at 4).
    // SECURITY: solc's external ABI decode runs in the dispatcher BEFORE the function body, so ALL of
    // (1) full 2-word static head present, (2) address dirty-high-bits, and (3) the bytes offset + [len]
    // [data] tail bounds must be validated HERE, before authorizeUpgrade. Otherwise a malformed offset (a)
    // slips past a non-owner as Error("not authorized") where solc EMPTY-reverts, and (b) lets an owner
    // upgrade + emit Upgraded off garbage bytes where solc EMPTY-reverts. Route the bytes tail through the
    // SAME jeth_calldata_dyn validator the standard @external (address,bytes) decoder uses (base = byte 4).
    out.push('if lt(calldatasize(), 0x44) { revert(0, 0) }');
    // require the address arg's high 96 bits are zero (a dirty word reverts empty, like solc's ABI decode).
    out.push(`if shr(160, calldataload(4)) { revert(0, 0) }`);
    out.push(`let _newImpl := and(calldataload(4), ${MASK})`);
    // validate + bind the bytes arg (dataPtr is a CALLDATA offset; len bounds-checked) BEFORE the gate.
    out.push('let _dataPtr, _dataLen := ' + this.calldataDyn() + '(calldataload(0x24))');
    // (1) the user access gate authorizeUpgrade(newImpl). A bare internal void function: call its userfn_.
    out.push(`${this.userFnName(fn.authorizeKey!)}(_newImpl)`);
    // (2) anti-brick: STATICCALL newImpl.proxiableUUID() (selector 0x52d1902d). A failed staticcall (incl.
    // a non-contract impl) OR a return shorter than 32 bytes -> revert ERC1967InvalidImplementation(newImpl).
    out.push(`mstore(0, ${PROXIABLE_UUID_SELECTOR}00000000000000000000000000000000000000000000000000000000)`);
    out.push('let _puOk := staticcall(gas(), _newImpl, 0, 4, 0, 0x20)');
    out.push('if or(iszero(_puOk), lt(returndatasize(), 0x20)) {');
    // ERC1967InvalidImplementation(address): selector + the newImpl word.
    out.push(
      `  mstore(0, ${ERC1967_INVALID_IMPLEMENTATION_SELECTOR}00000000000000000000000000000000000000000000000000000000)`,
    );
    out.push('  mstore(4, _newImpl)');
    out.push('  revert(0, 0x24)');
    out.push('}');
    // the returned bytes32 (the impl's claimed proxiable slot) must equal the EIP-1967 impl slot.
    out.push('let _slot := mload(0)');
    out.push(`if iszero(eq(_slot, ${EIP1967_IMPL_SLOT})) {`);
    // UUPSUnsupportedProxiableUUID(bytes32): selector + the returned slot.
    out.push(
      `  mstore(0, ${UUPS_UNSUPPORTED_PROXIABLE_UUID_SELECTOR}00000000000000000000000000000000000000000000000000000000)`,
    );
    out.push('  mstore(4, _slot)');
    out.push('  revert(0, 0x24)');
    out.push('}');
    // (3) the EIP-1967 upgrade (shared with proxyInit/upgradeProxy/the transparent admin upgrade):
    // require(isContract) -> sstore impl slot -> emit Upgraded(indexed) -> data.length>0 delegatecall+bubble.
    out.push(`if iszero(extcodesize(_newImpl)) { revert(0, 0) }`);
    out.push(`sstore(${EIP1967_IMPL_SLOT}, _newImpl)`);
    out.push(`log2(0, 0, ${UPGRADED_TOPIC}, _newImpl)`);
    // if data.length>0: copy the pre-validated calldata slice ([_dataPtr, +_dataLen)) into memory, then
    // delegatecall(gas(), newImpl, data) and bubble the callee's revert verbatim.
    out.push('if gt(_dataLen, 0) {');
    out.push('  let _mem := mload(0x40)');
    out.push('  calldatacopy(_mem, _dataPtr, _dataLen)');
    out.push('  let _ok := delegatecall(gas(), _newImpl, _mem, _dataLen, 0, 0)');
    out.push('  returndatacopy(0, 0, returndatasize())');
    out.push('  if iszero(_ok) { revert(0, returndatasize()) }');
    out.push('}');
    // the upgrade entry returns empty (OZ upgradeToAndCall returns void).
    out.push('return(0, 0)');
    return out;
  }

  /** Phase 2d (BEACON contract): emit the hand-written body of a synthesized `@beacon class` entry,
   *  byte-identical to OZ UpgradeableBeacon 5.x. Storage: owner at slot 0 (Ownable._owner), implementation
   *  at slot 1. Three kinds:
   *   - owner()          : return the owner address (SLOAD slot 0, masked).
   *   - implementation() : return the impl address (SLOAD slot 1, masked).
   *   - upgradeTo(address newImpl): onlyOwner (revert OwnableUnauthorizedAccount(caller) on a non-owner);
   *     require the address arg's high 96 bits are zero (solc ABI decode); require(isContract(newImpl));
   *     sstore slot 1; emit Upgraded(indexed newImpl); return empty. */
  private emitBeaconEntry(fn: FunctionIR): string[] {
    const out: string[] = [];
    const MASK = '0xffffffffffffffffffffffffffffffffffffffff';
    if (fn.beaconKind === 'owner') {
      out.push(`mstore(0, and(sload(0), ${MASK}))`);
      out.push('return(0, 0x20)');
      return out;
    }
    if (fn.beaconKind === 'implementation') {
      out.push(`mstore(0, and(sload(1), ${MASK}))`);
      out.push('return(0, 0x20)');
      return out;
    }
    // upgradeTo(address newImpl): onlyOwner -> isContract -> store slot 1 -> emit Upgraded -> return empty.
    out.push('if lt(calldatasize(), 0x24) { revert(0, 0) }');
    // onlyOwner: revert OwnableUnauthorizedAccount(msg.sender) when caller() != owner (slot 0).
    out.push(`if iszero(eq(caller(), and(sload(0), ${MASK}))) {`);
    out.push(`  mstore(0, ${OWNABLE_UNAUTHORIZED_SELECTOR}00000000000000000000000000000000000000000000000000000000)`);
    out.push('  mstore(4, caller())');
    out.push('  revert(0, 0x24)');
    out.push('}');
    // decode newImpl: a dirty high-96-bit word reverts empty (like solc's address ABI decode).
    out.push('if shr(160, calldataload(4)) { revert(0, 0) }');
    out.push(`let _newImpl := and(calldataload(4), ${MASK})`);
    // require(isContract(newImpl)) -> a clean empty revert on a non-contract (degenerate failure path).
    out.push('if iszero(extcodesize(_newImpl)) { revert(0, 0) }');
    out.push('sstore(1, _newImpl)');
    // emit Upgraded(address indexed implementation): an indexed-only event, log2 over no data.
    out.push(`log2(0, 0, ${UPGRADED_TOPIC}, _newImpl)`);
    out.push('return(0, 0)');
    return out;
  }

  private lowerCloneDeploy(e: Expr & { kind: 'cloneDeploy' }, ctx: LowerCtx, out: string[]): string {
    const { ptr, len } = this.buildCloneCreationCode(e.impl, e.args, ctx, out);
    const inst = this.fresh();
    if (e.salt) {
      const salt = this.fresh();
      out.push(`let ${salt} := ${this.lowerExpr(e.salt, ctx, out)}`);
      out.push(`let ${inst} := create2(0, ${ptr}, ${len}, ${salt})`);
    } else {
      out.push(`let ${inst} := create(0, ${ptr}, ${len})`);
    }
    out.push(`if iszero(${inst}) { revert(0, 0) }`);
    return inst;
  }

  /** predictClone* : the CREATE2 address keccak256(0xff ++ address(this) ++ salt ++ keccak256(creationCode))
   *  [12:] over the EXACT creation code clone* would deploy. Layout the 85-byte preimage at a scratch ptr:
   *  byte 11 = 0xff, [12..32) = address(this), [32..64) = salt, [64..96) = keccak(creationCode); hash the
   *  region [ptr+0x0b, +0x55) and mask to 160 bits. */
  private lowerPredictClone(e: Expr & { kind: 'predictClone' }, ctx: LowerCtx, out: string[]): string {
    const { ptr: codePtr, len } = this.buildCloneCreationCode(e.impl, e.args, ctx, out);
    const codeHash = this.fresh();
    out.push(`let ${codeHash} := keccak256(${codePtr}, ${len})`);
    const salt = this.fresh();
    out.push(`let ${salt} := ${this.lowerExpr(e.salt, ctx, out)}`);
    // Build the CREATE2 preimage in a fresh buffer (avoids clobbering the scratch 0x00/0x40 region).
    const p = this.fresh();
    out.push(`let ${p} := ${this.alloc()}(0x60)`);
    out.push(`mstore(add(${p}, 0x40), ${codeHash})`); // [0x40..0x60) codehash
    out.push(`mstore(add(${p}, 0x20), ${salt})`); // [0x20..0x40) salt
    out.push(`mstore(${p}, address())`); // [0x0c..0x20) address (right-aligned)
    out.push(`mstore8(add(${p}, 0x0b), 0xff)`); // byte 0x0b = 0xff
    const res = this.fresh();
    out.push(`let ${res} := and(keccak256(add(${p}, 0x0b), 0x55), 0xffffffffffffffffffffffffffffffffffffffff)`);
    return res;
  }

  /** Phase 6: perform a low-level CALL/STATICCALL. Lowers the data/value/gas operands, executes the
   *  opcode (args = the data blob's [add(ptr,0x20), mload(ptr)] region, output discarded), and copies
   *  the returndata into a FRESH memory bytes blob ([len][data], length-word at the returned ptr).
   *  Returns the success-bool register and the returndata-blob pointer. Used by both the checked
   *  (extCall expr) and raw (tryCall destructure) forms; the data blob is fully materialized BEFORE
   *  the call so it cannot alias the returndata buffer. */
  private emitExtCall(
    e: {
      op: 'call' | 'staticcall' | 'delegatecall';
      addr?: Expr;
      lib?: string;
      data: Expr;
      value?: Expr;
      gas?: Expr;
      bubble?: boolean;
      codeGuard?: boolean;
    },
    ctx: LowerCtx,
    out: string[],
  ): { okReg: string; dataPtr: string; addrReg: string } {
    // Phase B external library: a DELEGATECALL to a LINK-TIME library address. The target is
    // `linkersymbol("<lib>")` (solc emits the `__$..$__` placeholder + a linkReference); no addr/value/
    // gas operands. The whole rest (encode -> call -> capture returndata -> bubble) is shared with the
    // call/staticcall path.
    const isDelegate = e.op === 'delegatecall';
    // Evaluate operands left-to-right: target, then value (call only), then gas, then the data blob.
    const addr = this.fresh();
    if (isDelegate) {
      out.push(`let ${addr} := linkersymbol("${e.lib}")`);
    } else {
      out.push(`let ${addr} := ${this.lowerExpr(e.addr!, ctx, out)}`);
    }
    let valueExpr = '0';
    if (e.op === 'call' && e.value) {
      const v = this.fresh();
      out.push(`let ${v} := ${this.lowerExpr(e.value, ctx, out)}`);
      valueExpr = v;
    }
    let gasExpr = 'gas()'; // default: forward all remaining gas (matches solc's t.call(d))
    if (e.gas) {
      const g = this.fresh();
      out.push(`let ${g} := ${this.lowerExpr(e.gas, ctx, out)}`);
      gasExpr = g;
    }
    const { mp, len } = this.toMemory(this.lowerDynamic(e.data, ctx, out), out);
    const okReg = this.fresh();
    const argsOff = `add(${mp}, 0x20)`;
    if (e.op === 'staticcall') {
      out.push(`let ${okReg} := staticcall(${gasExpr}, ${addr}, ${argsOff}, ${len}, 0, 0)`);
    } else if (e.op === 'delegatecall') {
      out.push(`let ${okReg} := delegatecall(${gasExpr}, ${addr}, ${argsOff}, ${len}, 0, 0)`);
    } else {
      out.push(`let ${okReg} := call(${gasExpr}, ${addr}, ${valueExpr}, ${argsOff}, ${len}, 0, 0)`);
    }
    // Copy returndata into a fresh [len][data] blob (always captured, even on failure).
    const dataPtr = this.fresh();
    const rlen = this.fresh();
    out.push(`let ${rlen} := returndatasize()`);
    out.push(`let ${dataPtr} := ${this.alloc()}(add(0x20, and(add(${rlen}, 0x1f), not(0x1f))))`);
    out.push(`mstore(${dataPtr}, ${rlen})`);
    out.push(`returndatacopy(add(${dataPtr}, 0x20), 0, ${rlen})`);
    out.push(`if mod(${rlen}, 0x20) { mstore(add(add(${dataPtr}, 0x20), ${rlen}), 0) }`);
    // High-level typed interface call: bubble the callee's revert bytes VERBATIM, then guard against a
    // non-contract target. Order matches solc: failure-bubble first (an EOA call returns ok=true+empty,
    // so the bubble is skipped), then the extcodesize guard reverts empty for an EOA / never-deployed
    // address. (NO re-eval of the addr Expr - reuse the register evaluated above.)
    if (e.bubble) {
      out.push(`if iszero(${okReg}) { revert(add(${dataPtr}, 0x20), mload(${dataPtr})) }`);
    }
    if (e.codeGuard) {
      out.push(`if iszero(extcodesize(${addr})) { revert(0, 0) }`);
    }
    // Expose the addr register too: try/catch emits its codeGuard INSIDE the ok-branch without
    // re-evaluating the addr Expr (no double-eval of side effects).
    return { okReg, dataPtr, addrReg: addr };
  }

  /** Lower the ordered success checks of a `.call/.staticcall`. Each condition is evaluated with
   *  `this.ok` (the success bool) and `this.data` (the returndata blob) bound; the FIRST condition
   *  that is false reverts with its reason (the others are not evaluated past the revert). */
  private lowerSuccessChecks(
    checks: SuccessCheck[],
    okReg: string,
    dataPtr: string,
    ctx: LowerCtx,
    out: string[],
  ): void {
    if (checks.length === 0) return;
    this.ctxPush(ctx);
    this.ctxDeclare(ctx, EXT_CALL_OK_BINDING, okReg);
    this.ctxDeclare(ctx, EXT_CALL_DATA_BINDING, dataPtr);
    for (const chk of checks) {
      const cond = this.lowerExpr(chk.cond, ctx, out); // condition prep (e.g. abi.decode) emits to out
      const reasonLines = this.lowerRevertReason(chk.reason, ctx, out);
      out.push(`if iszero(${cond}) {`);
      for (const l of reasonLines) out.push('  ' + l);
      out.push('}');
    }
    this.ctxPop(ctx);
  }

  /** b[i] -> bytes1 (left-aligned), Panic(0x32) on out-of-bounds. */
  private lowerByteIndex(e: Expr & { kind: 'byteIndex' }, ctx: LowerCtx, out: string[]): string {
    // bytesN[i]: byte i of a fixed-bytes VALUE (a left-aligned word). Bound i < size (Panic 0x32),
    // then extract byte i (0-indexed from the MSB) and re-left-align it as a bytes1.
    if (e.base.type.kind === 'bytesN') {
      const size = e.base.type.size;
      const w = this.fresh();
      out.push(`let ${w} := ${this.lowerExpr(e.base, ctx, out)}`);
      const i = this.fresh();
      out.push(`let ${i} := ${this.lowerExpr(e.index, ctx, out)}`);
      out.push(`if iszero(lt(${i}, ${size})) { ${this.panic()}(0x32) }`);
      return `shl(248, byte(${i}, ${w}))`;
    }
    const ref = this.lowerDynamic(e.base, ctx, out);
    const len = this.fresh();
    out.push(`let ${len} := ${this.dynLen(ref)}`);
    const i = this.fresh();
    out.push(`let ${i} := ${this.lowerExpr(e.index, ctx, out)}`);
    out.push(`if iszero(lt(${i}, ${len})) { ${this.panic()}(0x32) }`);
    if (ref.src === 'calldata') return `and(calldataload(add(${ref.dataPtr}, ${i})), ${TOP_BYTE})`;
    if (ref.src === 'memory') return `and(mload(add(${ref.ptr}, add(0x20, ${i}))), ${TOP_BYTE})`;
    return `${this.strByteAt()}(${ref.slot}, ${i})`;
  }

  /** Encode a single dynamic value as ABI [offset=0x20][len][data] into a fresh
   *  memory buffer (allocated AFTER materialization to avoid aliasing). Returns
   *  the buffer ptr and a Yul expr for its total byte size. */
  private encodeDynToMem(ref: DynRef, out: string[]): { ptr: string; size: string } {
    const { mp, len } = this.toMemory(ref, out);
    const ptr = this.fresh();
    const padded = `and(add(${len}, 0x1f), not(0x1f))`;
    out.push(`let ${ptr} := ${this.alloc()}(add(0x40, ${padded}))`);
    out.push(`mstore(${ptr}, 0x20)`);
    out.push(`mcopy(add(${ptr}, 0x20), ${mp}, add(0x20, ${padded}))`);
    return { ptr, size: `add(0x40, ${padded})` };
  }

  /** Write a dynamic value into storage slot `slot` (short/long + clear old tail). */
  private storeDynamic(slot: string, ref: DynRef, out: string[]): void {
    const { mp, len } = this.toMemory(ref, out);
    out.push(`${this.storeStrMem()}(${slot}, ${mp}, ${len})`);
  }

  // dedup helper definitions ------------------------------------------------

  private alloc(): string {
    const name = 'jeth_alloc';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(size) -> ptr {
  ptr := mload(0x40)
  mstore(0x40, add(ptr, and(add(size, 0x1f), not(0x1f))))
}`,
      );
    }
    return name;
  }

  private arrayDataSlotHelper(): string {
    const name = 'jeth_array_data_slot';
    if (!this.helpers.has(name)) {
      this.helpers.set(name, `function ${name}(s) -> d {\n  mstore(0x00, s)\n  d := keccak256(0x00, 0x20)\n}`);
    }
    return name;
  }

  /** Decode a calldata dynamic-array param's (offset, length), bounds-checked
   *  exactly as solc (revert(0,0) on any malformation). */
  // Decode a dynamic array header at calldata offset `off` (relative to byte 4),
  // with `stride` bytes per element (32 for a value element, abiHeadWords*32 for a
  // static-struct element). Mirrors solc: bad offset / length / truncated payload
  // -> empty revert; len capped at 2^64 so stride*len cannot overflow a word.
  private calldataArray(): string {
    const name = 'jeth_calldata_array';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(off, stride) -> dataOff, len {
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  let p := add(4, off)
  if iszero(slt(add(p, 0x1f), calldatasize())) { revert(0, 0) }
  len := calldataload(p)
  if gt(len, 0xffffffffffffffff) { revert(0, 0) }
  dataOff := add(p, 0x20)
  if gt(add(dataOff, mul(len, stride)), calldatasize()) { revert(0, 0) }
}`,
      );
    }
    return name;
  }

  /** Decode a dynamic VALUE-array field of a calldata dynamic struct: the offset word at `offPtr`
   *  points (relative to the containing tuple `base`, spec 3.2) to the array's [len][elems]. Mirrors
   *  solc's array-member decode: UNSIGNED offset bound, length-word readable, and the FULL len*stride
   *  payload must fit within calldatasize (unlike the bytes/string helper jeth_calldata_dyn_at, which
   *  validates len+0x20 bytes and uses a SIGNED offset check). Returns (dataOff, len). */
  private calldataArrayAt(): string {
    const name = 'jeth_calldata_array_at';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(base, offPtr, stride) -> dataOff, len {
  let off := calldataload(offPtr)
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  let p := add(base, off)
  if iszero(slt(add(p, 0x1f), calldatasize())) { revert(0, 0) }
  len := calldataload(p)
  if gt(len, 0xffffffffffffffff) { revert(0, 0) }
  dataOff := add(p, 0x20)
  if gt(add(dataOff, mul(len, stride)), calldatasize()) { revert(0, 0) }
}`,
      );
    }
    return name;
  }

  /** Decode a string[]/bytes[] (array of dynamic elements) calldata header at outer
   *  offset `off` (relative to byte 4). Returns (tableStart, len): `tableStart` is
   *  the element-offset table = the word right after the length word, which is the
   *  base for each element's relative offset (spec section 4.2). Two inclusive range
   *  checks: the length word must be readable, and the L offset-table words must fit.
   *  Per-element payload bounds are validated lazily on each a[i] read. Any fault ->
   *  empty revert; len capped at 2^64 so L*32 cannot overflow. */
  private calldataDynArray(): string {
    const name = 'jeth_calldata_dyn_array';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(off) -> tableStart, len {
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  let p := add(4, off)
  if iszero(slt(add(p, 0x1f), calldatasize())) { revert(0, 0) }
  len := calldataload(p)
  if gt(len, 0xffffffffffffffff) { revert(0, 0) }
  tableStart := add(p, 0x20)
  if gt(add(tableStart, mul(len, 0x20)), calldatasize()) { revert(0, 0) }
}`,
      );
    }
    return name;
  }

  /** LAZY-ACCESS resolve of the i-th element of a string[]/bytes[] calldata array to
   *  its dynamic value (dataPtr, len) - the form solc uses for `return a[i]`, an
   *  individual element slice that is re-encoded directly from calldata (NOT decoded
   *  into a fresh memory array). `tableStart` (B) is the element-offset table base;
   *  element i's offset word is at tableStart + i*32; the data begins at tableStart +
   *  off_i (that word is the byte length; the payload follows). This mirrors solc's
   *  `access_calldata_tail` for a `bytes`/`string` member exactly (rule 1, measured):
   *    - SIGNED length-word-readable check `slt(off, calldatasize() - B - 31)` (a
   *      high-bit/wrapping off passes, an off in (calldatasize, 2^255) reverts EMPTY);
   *    - the pointer add WRAPS mod 2^256, an OOB length read returns 0;
   *    - the byte length is capped at 2^64-1 (else EMPTY);
   *    - a SIGNED payload-fits `sgt(lenPtr, calldatasize() - (len + 0x20))` (so a
   *      wrapped/high-bit lenPtr passes and yields the wrapped/zero element, while a
   *      declared length whose payload runs past calldatasize reverts EMPTY).
   *  The WHOLE-array echo (string[] -> string[] memory) uses calldataDynElemEcho. */
  private calldataDynElem(): string {
    const name = 'jeth_calldata_dyn_elem';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(tableStart, i) -> dataPtr, len {
  let offPtr := add(tableStart, mul(i, 0x20))
  let elOff := calldataload(offPtr)
  if iszero(slt(elOff, sub(sub(calldatasize(), tableStart), 0x1f))) { revert(0, 0) }
  let lenPtr := add(tableStart, elOff)
  len := calldataload(lenPtr)
  if gt(len, 0xffffffffffffffff) { revert(0, 0) }
  if sgt(lenPtr, sub(calldatasize(), add(len, 0x20))) { revert(0, 0) }
  dataPtr := add(lenPtr, 0x20)
}`,
      );
    }
    return name;
  }

  /** ECHO-DECODE resolve of the i-th element of a string[]/bytes[] calldata array,
   *  used when the WHOLE array is decoded into a fresh `string[] memory` (saEcho).
   *  solc's memory decoder rejects a wrapping/high-bit element offset with the UNSIGNED
   *  cap `gt(off, 2^64-1)` (no signed wrap acceptance), then requires the length word
   *  readable. The byte length is NOT capped here and the payload-fits is NOT applied:
   *  both fold into the per-element memory materialization, which raises Panic(0x41) on
   *  an oversized allocation (rule 3) and THEN validates the payload within calldatasize
   *  (EMPTY). Returns (dataPtr, len). */
  private calldataDynElemEcho(): string {
    const name = 'jeth_calldata_dyn_elem_echo';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(tableStart, i) -> dataPtr, len {
  let offPtr := add(tableStart, mul(i, 0x20))
  let elOff := calldataload(offPtr)
  if gt(elOff, 0xffffffffffffffff) { revert(0, 0) }
  let lenPtr := add(tableStart, elOff)
  if gt(add(lenPtr, 0x20), calldatasize()) { revert(0, 0) }
  len := calldataload(lenPtr)
  dataPtr := add(lenPtr, 0x20)
}`,
      );
    }
    return name;
  }

  /** LAZY-ACCESS resolve of the i-th inner array of a nested dynamic array T[][]
   *  (calldata) to its (dataOffset, innerLen) - the form solc uses for m[i], m[i][j],
   *  m[i].length (an individual inner-array slice, NOT a decode into fresh memory).
   *  `base` (B) is the pointer-region start (= the word after the outer length word),
   *  the base for each inner pointer (spec section 2.2). The pointer word at base + i*32
   *  gives inner i's offset to its LENGTH word; the element data starts at that length
   *  word + 32. Mirrors solc's `access_calldata_tail` for an array member exactly
   *  (rule 1, measured): SIGNED length-word-readable check `slt(off, calldatasize() -
   *  B - 31)` (a high-bit/wrapping off passes; the OOB length read returns 0); innerLen
   *  capped at 2^64-1; SIGNED payload-fits `sgt(lenPtr, calldatasize() - (innerLen*
   *  stride + 0x20))` (a wrapped lenPtr passes -> Panic 0x32 on the index, while a
   *  declared innerLen whose elements run past calldatasize reverts EMPTY). The WHOLE
   *  T[][] echo uses calldataInnerArrayEcho. */
  private calldataInnerArray(): string {
    const name = 'jeth_calldata_inner_array';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(base, i, stride) -> dataOff, innerLen {
  let offPtr := add(base, mul(i, 0x20))
  let innerOff := calldataload(offPtr)
  if iszero(slt(innerOff, sub(sub(calldatasize(), base), 0x1f))) { revert(0, 0) }
  let lenPtr := add(base, innerOff)
  innerLen := calldataload(lenPtr)
  if gt(innerLen, 0xffffffffffffffff) { revert(0, 0) }
  if sgt(lenPtr, sub(calldatasize(), add(mul(innerLen, stride), 0x20))) { revert(0, 0) }
  dataOff := add(lenPtr, 0x20)
}`,
      );
    }
    return name;
  }

  /** Navigate ONE offset-table level whose element has NO length word - an element that is itself a
   *  fixed-array-of-dynamic (Arr<string,N> = its N-word offset table) or a bytes/string header.
   *  Element idx's data starts at base + calldataload(base + idx*32) (offset relative to the table
   *  start). Mirrors calldataInnerArray's unsigned offset validation but reads no length word. */
  private calldataNestedOff(): string {
    const name = 'jeth_calldata_nested_off';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(base, idx) -> elemData {
  let off := calldataload(add(base, mul(idx, 0x20)))
  if iszero(slt(off, sub(sub(calldatasize(), base), 0x1f))) { revert(0, 0) }
  elemData := add(base, off)
}`,
      );
    }
    return name;
  }

  /** ECHO-DECODE resolve of the i-th inner array of a T[][], used when the WHOLE outer
   *  array is decoded into a fresh `T[][] memory` (mEcho). solc's memory decoder rejects
   *  a wrapping/high-bit inner offset with the UNSIGNED cap `gt(off, 2^64-1)` and then
   *  requires the length word readable. The innerLen cap and payload-fits fold into the
   *  per-inner memory materialization (Panic(0x41) on oversized allocation per rule 3,
   *  then payload-within-calldatasize EMPTY). Returns (dataOff, innerLen). */
  private calldataInnerArrayEcho(): string {
    const name = 'jeth_calldata_inner_array_echo';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(base, i) -> dataOff, innerLen {
  let offPtr := add(base, mul(i, 0x20))
  let innerOff := calldataload(offPtr)
  if gt(innerOff, 0xffffffffffffffff) { revert(0, 0) }
  let lenPtr := add(base, innerOff)
  if gt(add(lenPtr, 0x20), calldatasize()) { revert(0, 0) }
  innerLen := calldataload(lenPtr)
  dataOff := add(lenPtr, 0x20)
}`,
      );
    }
    return name;
  }

  /** Decode a DYNAMIC-struct (tuple) calldata param header at top-level offset `off`
   *  (relative to byte 4). Returns `tupleStart` = the tuple's first field word
   *  (= 4 + off), which is the base for the tuple's own field/dynamic offsets (spec
   *  section 3.2). Validates that the whole tuple head (`headSize` bytes) is readable;
   *  a bad / out-of-range offset -> EMPTY revert. off capped at 2^64. */
  private calldataTuple(): string {
    const name = 'jeth_calldata_tuple';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(off, headSize) -> tupleStart {
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  tupleStart := add(4, off)
  if gt(add(tupleStart, headSize), calldatasize()) { revert(0, 0) }
}`,
      );
    }
    return name;
  }

  /** Resolve a NESTED dynamic-struct field: `base` is the containing tuple start,
   *  `offPtr` is the calldata address of the field's offset word. The new tuple start
   *  = base + offset (offset relative to the containing tuple start, spec section 3.2).
   *  A nested dynamic STRUCT member is decoded eagerly (unlike a lazy bytes/array calldata
   *  slice), so solc uses the UNSIGNED form here, NOT the signed `access_calldata_tail`:
   *  `gt(off, 2^64-1)` rejects any wrapping/high-bit offset (measured: off=2^256-0x20,
   *  2^255, 2^64 all -> EMPTY), and the nested tuple head (`headSize` bytes) must be
   *  readable. Any fault -> EMPTY revert. Used identically by the lazy field-read path
   *  and the struct echo. */
  private calldataTupleAt(): string {
    const name = 'jeth_calldata_tuple_at';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(base, offPtr, headSize) -> tupleStart {
  if gt(add(offPtr, 0x20), calldatasize()) { revert(0, 0) }
  let off := calldataload(offPtr)
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  tupleStart := add(base, off)
  if gt(add(tupleStart, headSize), calldatasize()) { revert(0, 0) }
}`,
      );
    }
    return name;
  }

  private calldataDyn(): string {
    const name = 'jeth_calldata_dyn';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(off) -> dataPtr, len {
  let argsLen := sub(calldatasize(), 4)
  if or(lt(argsLen, 0x20), gt(off, sub(argsLen, 0x20))) { revert(0, 0) }
  let lp := add(4, off)
  len := calldataload(lp)
  if gt(len, sub(sub(argsLen, off), 0x20)) { revert(0, 0) }
  dataPtr := add(lp, 0x20)
}`,
      );
    }
    return name;
  }

  /** The MEMORY-decoder analogue of calldataDyn: decodes a top-level `bytes` argument EXACTLY as solc
   *  0.8.35 does when it materializes `bytes memory` via `abi.decode(msg.data[4:], (address, bytes))`
   *  (OZ's TransparentUpgradeableProxy). The args region base is byte 4; `off` is relative to it (so the
   *  bytes tail lives at `add(4, off)`). This mirrors solc's abi_decode_t_bytes_memory_ptr +
   *  abi_decode_available_length + array_allocation_size + finalize_allocation byte-for-byte:
   *    (C) offset cap:            `if gt(off, 2^64-1) { revert }`
   *    (D) length word readable:  `if iszero(slt(add(lp, 0x1f), calldatasize())) { revert }`  SIGNED
   *    (E) allocation panic:      len > 2^64-1 -> Panic(0x41); then the finalize_allocation overflow guard
   *        on `newFreePtr = mload(0x40) + roundUp32(roundUp32(len) + 0x20)` -> Panic(0x41). At the proxy
   *        entry nothing is allocated yet so mload(0x40)==0x80, matching solc's fresh free pointer.
   *    (F) payload fits:          `if gt(add(add(lp, 0x20), len), calldatasize()) { revert }`
   *  The caller has already validated the 2-word head (calldatasize >= 0x44) and the address arg's clean
   *  high bits (equivalent to solc's head-size + validator_revert_t_address_payable). Returns a CALLDATA
   *  dataPtr; the caller copies to memory before the delegatecall. This differs from calldataDyn (the
   *  `bytes calldata` form) ONLY in that an oversized length is a Panic(0x41), not an empty revert. */
  private calldataDynMem(): string {
    const name = 'jeth_calldata_dyn_mem';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(off) -> dataPtr, len {
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  let lp := add(4, off)
  if iszero(slt(add(lp, 0x1f), calldatasize())) { revert(0, 0) }
  len := calldataload(lp)
  if gt(len, 0xffffffffffffffff) { ${this.panic()}(0x41) }
  let allocSize := add(and(add(len, 31), not(31)), 0x20)
  let newFreePtr := add(mload(0x40), and(add(allocSize, 31), not(31)))
  if or(gt(newFreePtr, 0xffffffffffffffff), lt(newFreePtr, mload(0x40))) { ${this.panic()}(0x41) }
  if gt(add(add(lp, 0x20), len), calldatasize()) { revert(0, 0) }
  dataPtr := add(lp, 0x20)
}`,
      );
    }
    return name;
  }

  /** LAZY-ACCESS resolve of a bytes/string dynamic field inside a tuple - the form solc
   *  uses for `d.s.length` and `return d.s` (an individual calldata slice that is read
   *  or re-encoded directly, NOT decoded into a fresh memory struct). `base` (B) is the
   *  containing tuple start; `offPtr` is the calldata address of the field's offset word.
   *  The value lives at base + offset (spec section 3.2): that word is the byte length,
   *  the payload follows. Mirrors solc's `access_calldata_tail` for a bytes/string member
   *  exactly (rule 1, measured): SIGNED length-word-readable check `slt(off, calldatasize()
   *  - B - 31)` (a high-bit/wrapping off passes -> reads the wrapped/zero word; an off in
   *  (calldatasize, 2^255) reverts EMPTY); the byte length is capped at 2^64-1; a SIGNED
   *  payload-fits `sgt(lp, calldatasize() - (len + 0x20))` (a wrapped lp passes; a declared
   *  length running past calldatasize reverts EMPTY). The WHOLE-struct echo (return d) uses
   *  calldataDynAtEcho. */
  private calldataDynAt(): string {
    const name = 'jeth_calldata_dyn_at';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(base, offPtr) -> dataPtr, len {
  let off := calldataload(offPtr)
  if iszero(slt(off, sub(sub(calldatasize(), base), 0x1f))) { revert(0, 0) }
  let lp := add(base, off)
  len := calldataload(lp)
  if gt(len, 0xffffffffffffffff) { revert(0, 0) }
  if sgt(lp, sub(calldatasize(), add(len, 0x20))) { revert(0, 0) }
  dataPtr := add(lp, 0x20)
}`,
      );
    }
    return name;
  }

  /** ECHO-DECODE resolve of a bytes/string dynamic field, used when the WHOLE struct is
   *  decoded into a fresh `D memory` (return d). solc's memory decoder rejects a wrapping/
   *  high-bit field offset with the UNSIGNED cap `gt(off, 2^64-1)` and then requires the
   *  length word readable. The byte length is NOT capped and the payload-fits is NOT
   *  applied here: both fold into the memory materialization (Panic(0x41) on an oversized
   *  allocation per rule 3, then payload-within-calldatasize EMPTY). Returns (dataPtr, len). */
  private calldataDynAtEcho(): string {
    const name = 'jeth_calldata_dyn_at_echo';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(base, offPtr) -> dataPtr, len {
  let off := calldataload(offPtr)
  if gt(off, 0xffffffffffffffff) { revert(0, 0) }
  let lp := add(base, off)
  if gt(add(lp, 0x20), calldatasize()) { revert(0, 0) }
  len := calldataload(lp)
  dataPtr := add(lp, 0x20)
}`,
      );
    }
    return name;
  }

  private strLen(): string {
    const name = 'jeth_str_len';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(slot) -> l {
  let w := sload(slot)
  switch and(w, 1)
  case 0 { l := shr(1, and(w, 0xff)) }
  default { l := shr(1, sub(w, 1)) }
}`,
      );
    }
    return name;
  }

  /** Copy a storage bytes/string at `slot` directly to memory `dst` as [len][right-
   *  padded data], WITHOUT allocating (so it never clobbers an output blob under
   *  construction at the free pointer). Returns the byte size written. */
  private copyStrToMem(): string {
    const name = 'jeth_copy_str_to_mem';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(slot, dst) -> size {
  let w := sload(slot)
  let len
  switch and(w, 1)
  case 0 {
    len := shr(1, and(w, 0xff))
    mstore(dst, len)
    mstore(add(dst, 0x20), and(w, not(0xff)))
  }
  default {
    len := shr(1, sub(w, 1))
    mstore(dst, len)
    let nwords := div(add(len, 0x1f), 0x20)
    mstore(0x00, slot)
    let base := keccak256(0x00, 0x20)
    for { let i := 0 } lt(i, nwords) { i := add(i, 1) } {
      mstore(add(add(dst, 0x20), mul(i, 0x20)), sload(add(base, i)))
    }
  }
  size := add(0x20, and(add(len, 0x1f), not(0x1f)))
}`,
      );
    }
    return name;
  }

  private loadStr(): string {
    const name = 'jeth_load_str';
    if (!this.helpers.has(name)) {
      this.alloc();
      this.helpers.set(
        name,
        `function ${name}(slot) -> mp, len {
  let w := sload(slot)
  switch and(w, 1)
  case 0 {
    len := shr(1, and(w, 0xff))
    mp := jeth_alloc(0x40)
    mstore(mp, len)
    mstore(add(mp, 0x20), and(w, not(0xff)))
  }
  default {
    len := shr(1, sub(w, 1))
    let nwords := div(add(len, 0x1f), 0x20)
    mp := jeth_alloc(add(0x20, mul(nwords, 0x20)))
    mstore(mp, len)
    mstore(0x00, slot)
    let base := keccak256(0x00, 0x20)
    for { let i := 0 } lt(i, nwords) { i := add(i, 1) } {
      mstore(add(add(mp, 0x20), mul(i, 0x20)), sload(add(base, i)))
    }
  }
}`,
      );
    }
    return name;
  }

  private strByteAt(): string {
    const name = 'jeth_str_byte_at';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(slot, i) -> r {
  let w := sload(slot)
  switch and(w, 1)
  case 0 { r := and(shl(mul(i, 8), w), ${TOP_BYTE}) }
  default {
    mstore(0x00, slot)
    let base := keccak256(0x00, 0x20)
    r := and(shl(mul(mod(i, 0x20), 8), sload(add(base, div(i, 0x20)))), ${TOP_BYTE})
  }
}`,
      );
    }
    return name;
  }

  /** Write byte i (bounds-checked) of a storage `bytes` to the bytes1 value `b` (left-aligned, byte in
   *  the top byte). Same short/long layout as strByteAt: short = data in the high bytes of the slot,
   *  long = at keccak(slot)+i/32. Read-modify-writes only the target byte; the length is unchanged. */
  private strByteSet(): string {
    const name = 'jeth_str_byte_set';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(slot, i, b) {
  let w := sload(slot)
  switch and(w, 1)
  case 0 {
    if iszero(lt(i, and(shr(1, w), 0x7f))) { ${this.panic()}(0x32) }
    let sh := mul(i, 8)
    sstore(slot, or(and(w, not(shr(sh, ${TOP_BYTE}))), shr(sh, and(b, ${TOP_BYTE}))))
  }
  default {
    if iszero(lt(i, shr(1, sub(w, 1)))) { ${this.panic()}(0x32) }
    mstore(0x00, slot)
    let ds := add(keccak256(0x00, 0x20), div(i, 0x20))
    let sh := mul(mod(i, 0x20), 8)
    sstore(ds, or(and(sload(ds), not(shr(sh, ${TOP_BYTE}))), shr(sh, and(b, ${TOP_BYTE}))))
  }
}`,
      );
    }
    return name;
  }

  /** Append byte `b` (a bytes1, byte in the top byte) to a storage `bytes`. Short form stays short
   *  until 31 bytes; the 31->32 push transitions to long (data moved to keccak(slot)); long appends at
   *  keccak(slot)+len/32. Matches solc's storage layout byte-for-byte (verified against raw slots). */
  private strPush(): string {
    const name = 'jeth_str_push';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(slot, b) {
  let w := sload(slot)
  switch and(w, 1)
  case 0 {
    let len := shr(1, and(w, 0xff))
    switch lt(len, 31)
    case 1 {
      let nw := or(w, shr(mul(len, 8), and(b, ${TOP_BYTE})))
      sstore(slot, or(and(nw, not(0xff)), shl(1, add(len, 1))))
    }
    default {
      mstore(0x00, slot)
      sstore(keccak256(0x00, 0x20), or(and(w, not(0xff)), shr(248, and(b, ${TOP_BYTE}))))
      sstore(slot, 65)
    }
  }
  default {
    let len := shr(1, sub(w, 1))
    mstore(0x00, slot)
    let ds := add(keccak256(0x00, 0x20), div(len, 0x20))
    let sh := mul(mod(len, 0x20), 8)
    sstore(ds, or(and(sload(ds), not(shr(sh, ${TOP_BYTE}))), shr(sh, and(b, ${TOP_BYTE}))))
    sstore(slot, add(w, 2))
  }
}`,
      );
    }
    return name;
  }

  /** Remove the last byte of a storage `bytes` (Panic 0x31 if empty). Short pop zeroes the byte +
   *  decrements; long pop zeroes the freed byte; the 32->31 pop transitions back to short (data moved
   *  inline, keccak(slot) word freed). Matches solc's storage layout byte-for-byte. */
  private strPop(): string {
    const name = 'jeth_str_pop';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(slot) {
  let w := sload(slot)
  switch and(w, 1)
  case 0 {
    let len := shr(1, and(w, 0xff))
    if iszero(len) { ${this.panic()}(0x31) }
    let nw := and(w, not(shr(mul(sub(len, 1), 8), ${TOP_BYTE})))
    sstore(slot, or(and(nw, not(0xff)), shl(1, sub(len, 1))))
  }
  default {
    let len := shr(1, sub(w, 1))
    switch eq(len, 32)
    case 1 {
      mstore(0x00, slot)
      let base := keccak256(0x00, 0x20)
      let kd0 := sload(base)
      sstore(base, 0)
      sstore(slot, or(and(kd0, not(0xff)), 62))
    }
    default {
      mstore(0x00, slot)
      let ds := add(keccak256(0x00, 0x20), div(sub(len, 1), 0x20))
      let sh := mul(mod(sub(len, 1), 0x20), 8)
      sstore(ds, and(sload(ds), not(shr(sh, ${TOP_BYTE}))))
      sstore(slot, sub(w, 2))
    }
  }
}`,
      );
    }
    return name;
  }

  /** Clear a storage bytes/string slot to empty: zero the header AND (for a long
   *  value) its keccak(slot) data slots. Matches solc's full clear on pop/delete. */
  private clearStr(): string {
    const name = 'jeth_clear_str';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(slot) {
  let oldw := sload(slot)
  sstore(slot, 0)
  if and(oldw, 1) {
    let oldLen := shr(1, sub(oldw, 1))
    let oldWords := div(add(oldLen, 0x1f), 0x20)
    mstore(0x00, slot)
    let base := keccak256(0x00, 0x20)
    for { let i := 0 } lt(i, oldWords) { i := add(i, 1) } { sstore(add(base, i), 0) }
  }
}`,
      );
    }
    return name;
  }

  private storeStrMem(): string {
    const name = 'jeth_store_str_mem';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(slot, mp, len) {
  let oldw := sload(slot)
  let oldLen := 0
  if and(oldw, 1) { oldLen := shr(1, sub(oldw, 1)) }
  let oldWords := div(add(oldLen, 0x1f), 0x20)
  mstore(0x00, slot)
  let base := keccak256(0x00, 0x20)
  switch lt(len, 0x20)
  case 1 {
    let dataWord := 0
    if len { dataWord := mload(add(mp, 0x20)) }
    let keepMask := shl(mul(sub(32, len), 8), not(0))
    sstore(slot, or(and(dataWord, keepMask), mul(len, 2)))
    for { let i := 0 } lt(i, oldWords) { i := add(i, 1) } { sstore(add(base, i), 0) }
  }
  default {
    sstore(slot, add(mul(len, 2), 1))
    let nwords := div(add(len, 0x1f), 0x20)
    for { let i := 0 } lt(i, nwords) { i := add(i, 1) } {
      let wv := mload(add(add(mp, 0x20), mul(i, 0x20)))
      if eq(i, sub(nwords, 1)) {
        let rem := mod(len, 0x20)
        if rem { wv := and(wv, shl(mul(sub(32, rem), 8), not(0))) }
      }
      sstore(add(base, i), wv)
    }
    for { let i := nwords } lt(i, oldWords) { i := add(i, 1) } { sstore(add(base, i), 0) }
  }
}`,
      );
    }
    return name;
  }

  /** Derive the storage slot for this.m[k]...[k]: keccak256(keyWord . p) per level,
   *  recursive for nested mappings, using scratch 0x00-0x3f. The key's register
   *  word IS the hash key (uint zero-ext, int sign-ext, address zero-ext, bytesN
   *  left-aligned all match Solidity's padded key). Returns the final slot temp. */
  private mappingSlot(baseSlot: bigint, keys: Expr[], ctx: LowerCtx, out: string[]): string {
    let slot = String(baseSlot);
    for (const key of keys) {
      if (isBytesLike(key.type)) {
        // bytes/string key: slot = keccak256(keyContent . slotWord) over the RAW content bytes
        // (unpadded) concatenated with the 32-byte slot (solc's mapping-with-dynamic-key rule).
        const { mp, len } = this.toMemory(this.lowerDynamic(key, ctx, out), out);
        const ptr = this.fresh();
        out.push(`let ${ptr} := mload(0x40)`);
        out.push(`mcopy(${ptr}, add(${mp}, 0x20), ${len})`); // copy content to a fresh scratch region
        out.push(`mstore(add(${ptr}, ${len}), ${slot})`); // append the slot word right after the content
        const t = this.fresh();
        out.push(`let ${t} := keccak256(${ptr}, add(${len}, 0x20))`);
        slot = t;
        continue;
      }
      const k = this.lowerExpr(key, ctx, out);
      const t = this.fresh();
      out.push(`mstore(0x00, ${k})`);
      out.push(`mstore(0x20, ${slot})`);
      out.push(`let ${t} := keccak256(0x00, 0x40)`);
      slot = t;
    }
    return slot;
  }

  /** Store a register VALUE into a value-typed lvalue (local / state / mapping / nested
   *  place / array element). Factored from the assign-statement handler; used by the
   *  expression-position ++/-- lowering. */
  /** Evaluate internal-call arguments LEFT-to-RIGHT (solc order), freezing each into a fresh
   *  temp so a later arg's side effect cannot disturb an earlier arg's already-computed value.
   *  A STATIC struct argument is passed by reference (its memory pointer); a freshly constructed
   *  one (structNew) is allocated to memory first. */
  private lowerCallArgs(args: Expr[], ctx: LowerCtx, out: string[]): string[] {
    return args.map((a) => {
      // an aggregate arg (struct / dynamic value array / bytes / string) is passed BY MEMORY
      // REFERENCE (alias for a memory source, fresh copy for storage/calldata/literal); a value arg
      // is a plain register.
      const isAgg = a.type.kind === 'struct' || a.type.kind === 'array' || isBytesLike(a.type);
      // W6A: an internal callee receives the argument image and can mutate it (or expect writes to
      // show through a captured source), so a constructed arg is a PERSISTENT capture even inside
      // an enclosing transient encode/store region - force the flag back.
      const reg = isAgg
        ? this.inPersistentCapture(() => this.aggArgToMemPtr(a, ctx, out))
        : this.lowerExpr(a, ctx, out);
      const t = this.fresh();
      out.push(`let ${t} := ${reg}`);
      return t;
    });
  }

  /** Evaluate a tuple destructuring source into one value register per component (left-to-right).
   *  A multi-value internal call yields all components at once (`let r0, r1 := f(args)`); a tuple
   *  of expressions evaluates each into its own temp. */
  private lowerDestructureSource(source: DestructureSource, ctx: LowerCtx, out: string[]): string[] {
    if (source.kind === 'call') {
      const args = this.lowerCallArgs(source.args, ctx, out);
      const n = this.funcs.get(source.fn)?.returnTypes?.length ?? 0;
      const regs = Array.from({ length: n }, () => this.fresh());
      out.push(`let ${regs.join(', ')} := ${this.userFnName(source.fn)}(${args.join(', ')})`);
      return regs;
    }
    if (source.kind === 'extCall') {
      // `let [ok, ret] = addr.tryCall/tryStaticcall({...})`: raw CALL, no checks. Two components:
      // the success bool and the returndata bytes blob pointer (the bytes ret binds as a memory local
      // exactly like any [len][data] pointer; the analyzer registered it in memDynLocals).
      const { okReg, dataPtr } = this.emitExtCall(source, ctx, out);
      return [okReg, dataPtr];
    }
    if (source.kind === 'abiDecode') {
      // `let [a, b] = abi.decode(data, [T1, T2])`: decode each component into its own register (a value
      // word, or a memory image pointer for a bytes/string/array/struct component; the analyzer
      // registered the reference components in the matching side-tables, like a localDecl).
      return this.lowerAbiDecode(source.data, source.types, ctx, out);
    }
    if (source.kind === 'tryRecover') {
      // `let [ok, signer] = tryRecover(hash, sig)`: the never-reverting OZ ECDSA.tryRecover. Read r/s/v
      // from the memory image of `sig`; init (0, 0); only a 65-byte, non-high-s, non-zero-signer case
      // yields (1, signer). Mirrors the recover gate without any revert (every bad case is (false, 0)).
      const hash = this.lowerExpr(source.hash, ctx, out);
      const { mp, len } = this.toMemory(this.lowerDynamic(source.sig, ctx, out), out);
      const okReg = this.fresh();
      const signerReg = this.fresh();
      out.push(`let ${okReg} := 0`);
      out.push(`let ${signerReg} := 0`);
      out.push(`if eq(${len}, 65) {`);
      const rr = this.fresh();
      const ss = this.fresh();
      const vv = this.fresh();
      out.push(`  let ${rr} := mload(add(${mp}, 0x20))`);
      out.push(`  let ${ss} := mload(add(${mp}, 0x40))`);
      out.push(`  let ${vv} := byte(0, mload(add(${mp}, 0x60)))`);
      out.push(`  if iszero(gt(${ss}, ${HALF_ORDER})) {`);
      const inner: string[] = [];
      const sig = this.emitEcrecover(hash, vv, rr, ss, inner);
      for (const l of inner) out.push('    ' + l);
      out.push(`    if ${sig} { ${okReg} := 1 ${signerReg} := ${sig} }`);
      out.push('  }');
      out.push('}');
      return [okReg, signerReg];
    }
    if (source.kind === 'pointEvaluation') {
      // `const [fe, modulus] = pointEvaluation(versionedHash, z, y, commitment, proof)`: build the
      // 192-byte input (vh||z||y||commitment(48)||proof(48)) in a FRESH FMP buffer (NOT 0x00-0x40 scratch,
      // which the staticcall writes 64 bytes of output to), staticcall 0x0a, revert EMPTY on failure, and
      // bind [mload(0x00), mload(0x20)] (the constant success words FIELD_ELEMENTS_PER_BLOB, BLS_MODULUS).
      const vh = this.lowerExpr(source.versionedHash, ctx, out);
      const z = this.lowerExpr(source.z, ctx, out);
      const y = this.lowerExpr(source.y, ctx, out);
      const c = this.toMemory(this.lowerDynamic(source.commitment, ctx, out), out);
      const pr = this.toMemory(this.lowerDynamic(source.proof, ctx, out), out);
      out.push(`if iszero(eq(${c.len}, 48)) { revert(0, 0) }`);
      out.push(`if iszero(eq(${pr.len}, 48)) { revert(0, 0) }`);
      const inp = this.fresh();
      out.push(`let ${inp} := ${this.alloc()}(192)`);
      out.push(`mstore(${inp}, ${vh})`);
      out.push(`mstore(add(${inp}, 0x20), ${z})`);
      out.push(`mstore(add(${inp}, 0x40), ${y})`);
      out.push(`mcopy(add(${inp}, 0x60), add(${c.mp}, 0x20), 48)`);
      out.push(`mcopy(add(${inp}, 0x90), add(${pr.mp}, 0x20), 48)`);
      out.push(`if iszero(staticcall(gas(), 0x0a, ${inp}, 192, 0x00, 0x40)) { revert(0, 0) }`);
      const feReg = this.fresh();
      const modReg = this.fresh();
      out.push(`let ${feReg} := mload(0x00)`);
      out.push(`let ${modReg} := mload(0x20)`);
      return [feReg, modReg];
    }
    return source.values.map((v) => {
      const r = this.fresh();
      out.push(`let ${r} := ${this.lowerExpr(v, ctx, out)}`);
      return r;
    });
  }

  /** Apply runtime fixed-array index steps (xs[i].pre[j]) to a base memory pointer: for each step lower
   *  the index, bounds-check it (Panic 0x32), and advance by index * strideBytes. Steps run in chain
   *  order, matching solc's bounds-check sequence. Returns the final pointer register. */
  private applyRunSteps(ptr: string, runSteps: ArrIndexStep[], ctx: LowerCtx, out: string[]): string {
    let cur = ptr;
    for (const step of runSteps) {
      const idx = this.fresh();
      out.push(`let ${idx} := ${this.lowerExpr(step.index, ctx, out)}`);
      out.push(`if iszero(lt(${idx}, ${step.length})) { ${this.panic()}(0x32) }`);
      const next = this.fresh();
      out.push(`let ${next} := add(${cur}, mul(${idx}, ${step.strideBytes}))`);
      cur = next;
    }
    return cur;
  }

  /** The memory pointer to a field/element within a memory-array struct element's image: the element
   *  image pointer (aggToMemPtr of the base) + the static word offset + any runtime index steps. Shared
   *  by the aggFieldRead read, aggToMemPtr (whole-aggregate leaf), and the aggFieldStore write. */
  private aggFieldPtr(base: Expr, wordOffset: number, runSteps: ArrIndexStep[] | undefined, ctx: LowerCtx, out: string[]): string {
    const ptr = this.aggToMemPtr(base, ctx, out);
    let cur = wordOffset === 0 ? ptr : `add(${ptr}, ${wordOffset * 32})`;
    if (runSteps && runSteps.length) {
      const b = this.fresh();
      out.push(`let ${b} := ${cur}`);
      cur = this.applyRunSteps(b, runSteps, ctx, out);
    }
    return cur;
  }

  // Walk a nested-dynamic-struct deref chain: start at the dyn-struct local's image, then mload each head
  // word in derefWords (a pointer to the next nested image). Returns the innermost struct's image pointer.
  private nestedInnerPtr(local: string, derefWords: number[], ctx: LowerCtx, out: string[]): string {
    let ptr = this.ctxLookup(ctx, local);
    for (const off of derefWords) {
      const next = this.fresh();
      out.push(`let ${next} := mload(${off === 0 ? ptr : `add(${ptr}, ${off * 32})`})`);
      ptr = next;
    }
    return ptr;
  }

  private lowerAssignValue(target: LValue, valueReg: string, ctx: LowerCtx, out: string[]): void {
    if (target.kind === 'memDynNestedFieldStore') {
      // v.t.n = x (value leaf of a nested dynamic struct): deref the chain to the inner image, mstore at
      // the final word. (The deref re-point form is handled in the assignment dispatch, not here.)
      const inner = this.nestedInnerPtr(target.local, target.derefWords, ctx, out);
      out.push(`mstore(${target.finalWord === 0 ? inner : `add(${inner}, ${target.finalWord * 32})`}, ${valueReg})`);
      return;
    }
    if (target.kind === 'local') {
      out.push(`${this.ctxLookup(ctx, target.varName)} := ${valueReg}`);
      return;
    }
    if (target.kind === 'state') {
      for (const l of this.storeState(target.type, String(target.slot), target.offset, valueReg)) out.push(l);
      return;
    }
    if (target.kind === 'immutableStaged') {
      // assign the staged shadow (a jeth_constructor return var); baked via setimmutable at the end.
      out.push(`${ctx.immStaged!.get(target.name)!} := ${valueReg}`);
      // Mirror into the reserved creation-block memory cell (see lowerStmt 'assign' / ctorImmShadow).
      if (ctx.ctorImmShadow && ctx.ctorImmShadow.has(target.name))
        out.push(`mstore(${ctx.ctorImmShadow.get(target.name)!}, ${valueReg})`);
      return;
    }
    if (target.kind === 'mapping') {
      const slot = this.mappingSlot(target.baseSlot, target.keys, ctx, out);
      for (const l of this.storeState(target.type, slot, 0, valueReg)) out.push(l);
      return;
    }
    if (target.kind === 'place') {
      const p = this.lowerPlace(target.path, ctx, out);
      // a packed element with a RUNTIME byte offset uses packedStore; otherwise constant-offset.
      if (p.byteShift !== undefined) this.packedStore(target.type, p.slot, p.byteShift, valueReg, out);
      else for (const l of this.storeState(target.type, p.slot, p.offset, valueReg)) out.push(l);
      return;
    }
    if (target.kind === 'memField') {
      const ptr = this.ctxLookup(ctx, target.local);
      out.push(`mstore(${target.wordOffset === 0 ? ptr : `add(${ptr}, ${target.wordOffset * 32})`}, ${valueReg})`);
      return;
    }
    if (target.kind === 'memElem') {
      const ptr = this.ctxLookup(ctx, target.local);
      const base = target.wordOffset ? `add(${ptr}, ${target.wordOffset * 32})` : ptr;
      const i = this.fresh();
      out.push(`let ${i} := ${this.lowerExpr(target.index, ctx, out)}`);
      out.push(`if iszero(lt(${i}, ${target.length})) { ${this.panic()}(0x32) }`);
      out.push(`mstore(add(${base}, mul(${i}, 0x20)), ${valueReg})`);
      return;
    }
    if (target.kind === 'arrayElem') {
      const ref = this.lowerArrayRef(target.arr, ctx, out);
      const idx = this.fresh();
      out.push(`let ${idx} := ${this.lowerExpr(target.index, ctx, out)}`);
      if (ref.src === 'fixed') {
        out.push(`if iszero(lt(${idx}, ${ref.length})) { ${this.panic()}(0x32) }`);
        this.arrayElemStore(target.type, String(ref.baseSlot), idx, valueReg, out);
      } else if (ref.src === 'storage') {
        out.push(`if iszero(lt(${idx}, sload(${ref.lenSlot}))) { ${this.panic()}(0x32) }`);
        const data = this.arrayDataSlot(ref.lenSlot, out);
        this.arrayElemStore(target.type, data, idx, valueReg, out);
      } else if (ref.src === 'memory') {
        out.push(`if iszero(lt(${idx}, mload(${ref.ptr}))) { ${this.panic()}(0x32) }`);
        out.push(`mstore(add(${ref.ptr}, add(0x20, mul(${idx}, 0x20))), ${valueReg})`);
      } else {
        throw new UnsupportedError('cannot ++/-- a calldata array element');
      }
      return;
    }
    if (target.kind === 'aggFieldStore') {
      // a VALUE leaf (xs[i].a = v / xs[i].pre[j] = v): store one word at the field pointer (element image
      // + static offset + runtime index steps). No mask - the RHS is coerced to the field type by the
      // analyzer. (An AGGREGATE leaf xs[i].q = Q(..) is an image copy, handled in the 'assign' codegen.)
      const cur = this.aggFieldPtr(target.base, target.wordOffset, target.runSteps, ctx, out);
      out.push(`mstore(${cur}, ${valueReg})`);
      return;
    }
    throw new UnsupportedError(`cannot ++/-- an lvalue of kind '${target.kind}'`);
  }

  private lowerGlobal(e: Expr & { kind: 'global' }): string {
    switch (e.op) {
      case 'caller':
        return 'caller()';
      case 'callvalue':
        return 'callvalue()';
      case 'origin':
        return 'origin()';
      case 'gasprice':
        return 'gasprice()';
      case 'address':
        return 'address()';
      case 'timestamp':
        return 'timestamp()';
      case 'number':
        return 'number()';
      case 'chainid':
        return 'chainid()';
      case 'coinbase':
        return 'coinbase()';
      case 'basefee':
        return 'basefee()';
      case 'gaslimit':
        return 'gaslimit()';
      case 'prevrandao':
        return 'prevrandao()';
      case 'blobbasefee':
        return 'blobbasefee()';
      case 'gas':
        return 'gas()';
      case 'msgsig':
        // bytes4 left-aligned: high 4 bytes = selector. Matches solc.
        return 'and(calldataload(0), 0xffffffff00000000000000000000000000000000000000000000000000000000)';
    }
  }

  private lowerCast(e: Expr & { kind: 'cast' }, ctx: LowerCtx, out: string[]): string {
    const { from, type: to } = e;
    // bytesN(bytes): the first N content bytes (left-aligned), zero-padded if the value is shorter.
    // The operand is a dynamic [len][data] value, not a word, so materialize it and read its first word.
    if (from.kind === 'bytes' && to.kind === 'bytesN') {
      const { mp } = this.toMemory(this.lowerDynamic(e.operand, ctx, out), out);
      const w = this.fresh();
      out.push(`let ${w} := mload(add(${mp}, 0x20))`); // first content word: left-aligned, zero-padded
      if (to.size === 32) return w;
      const mask = toWord(((1n << BigInt(to.size * 8)) - 1n) << BigInt((32 - to.size) * 8));
      return `and(${w}, ${mask})`;
    }
    const v = this.lowerExpr(e.operand, ctx, out);
    // enum TARGET (integer -> enum, `Color(x)`): solc range-checks `x < memberCount` and reverts
    // Panic 0x21 when out of range (the unsigned `lt` naturally rejects negative ints). The value
    // is already a valid small uint8 afterward, so just return it. (enum -> integer needs no case:
    // the integer branch below returns the value unchanged.)
    const toEnum = (to as { enumMembers?: string[] }).enumMembers;
    if (to.kind === 'uint' && toEnum !== undefined) {
      out.push(`if iszero(lt(${v}, ${toEnum.length})) { ${this.panic()}(0x21) }`);
      return v;
    }
    // address <-> uint160 and address <-> address(payable): identical register word.
    if (to.kind === 'address' && from.kind === 'address') return v;
    if (to.kind === 'address' && from.kind === 'uint' && from.bits === 160) return v;
    if (to.kind === 'uint' && to.bits === 160 && from.kind === 'address') return v;
    // address (right-aligned low 20 bytes) <-> bytes20 (left-aligned high 20 bytes).
    if (to.kind === 'bytesN' && to.size === 20 && from.kind === 'address') return `shl(96, ${v})`;
    if (to.kind === 'address' && from.kind === 'bytesN' && from.size === 20) return `shr(96, ${v})`;
    // implicit widening (uintN->uintM, intN->intM, bytesN->bytesM, M>=N): a canonical
    // narrow value is already a valid wider value (uint: high bits 0; int: sign-extended;
    // bytesN: left-aligned), so the conversion is a no-op at the word level.
    if (isImplicitWiden(from, to)) return v;
    // bool(x) identity self-cast: a bool is already a canonical 0/1 word, so the conversion is a no-op.
    if (from.kind === 'bool' && to.kind === 'bool') return v;
    // integer <-> integer (explicit). uint target -> keep low toBits; int target ->
    // sign-extend the low toBits. Same-size int<->uint reinterprets the bits.
    if ((from.kind === 'uint' || from.kind === 'int') && (to.kind === 'uint' || to.kind === 'int')) {
      if (to.kind === 'uint') return to.bits === 256 ? v : `and(${v}, ${uintMaxHex(to.bits)})`;
      return to.bits === 256 ? v : `signextend(${to.bits / 8 - 1}, ${v})`;
    }
    // bytesN -> bytesM (narrowing; widening handled above): keep the high M bytes.
    if (from.kind === 'bytesN' && to.kind === 'bytesN') {
      const mask = toWord(((1n << BigInt(to.size * 8)) - 1n) << BigInt((32 - to.size) * 8));
      return `and(${v}, ${mask})`;
    }
    // uintN <-> bytesM of equal byte size: uint is right-aligned (low M bytes), bytesM is
    // left-aligned (high M bytes); shift by (32 - M) bytes between the two layouts.
    if (from.kind === 'uint' && to.kind === 'bytesN') return to.size === 32 ? v : `shl(${(32 - to.size) * 8}, ${v})`;
    if (from.kind === 'bytesN' && to.kind === 'uint')
      return from.size === 32 ? v : `shr(${(32 - from.size) * 8}, ${v})`;
    throw new UnsupportedError(`cast ${from.kind} -> ${to.kind} is not supported`);
  }

  private loadState(t: JethType, slot: string, offset: number): string {
    const size = storageByteSize(t);
    if (size === 32 && offset === 0) return `sload(${slot})`;
    const shift = BigInt(offset * 8);
    const raw = `shr(${shift}, sload(${slot}))`;
    if (t.kind === 'int') return `signextend(${t.bits / 8 - 1}, ${raw})`;
    const mask = (1n << BigInt(size * 8)) - 1n;
    const field = `and(${raw}, ${toWord(mask)})`;
    // bytesN must be returned in left-aligned register form.
    if (t.kind === 'bytesN') return `shl(${(32 - size) * 8}, ${field})`;
    return field;
  }

  private lowerUnary(e: Expr & { kind: 'unary' }, ctx: LowerCtx, out: string[]): string {
    const operand = this.lowerExpr(e.operand, ctx, out);
    switch (e.op) {
      case '!':
        return `iszero(${operand})`;
      case '~': {
        const not = `not(${operand})`;
        // keep uintN in range after complement
        if (e.type.kind === 'uint' && e.type.bits < 256) return `and(${not}, ${uintMaxHex(e.type.bits)})`;
        // bytesN ~: keep the low padding bytes zero (not(..) would set them to ff), matching solc.
        if (e.type.kind === 'bytesN' && e.type.size < 32) return `and(${not}, ${bytesNHighMaskHex(e.type.size)})`;
        return not;
      }
      case '-': {
        if (e.type.kind !== 'int') throw new UnsupportedError('unary - on non-int');
        // unchecked negation wraps (0 - x mod 2^bits); checked reverts at INT_MIN.
        if (e.unchecked) return this.wrapToType(e.type, `sub(0, ${operand})`);
        const helper = this.checkedSubInt(e.type.bits);
        return `${helper}(0, ${operand})`;
      }
    }
  }

  private lowerBinary(e: Expr & { kind: 'binary' }, ctx: LowerCtx, out: string[]): string {
    // Short-circuiting && / || must NOT evaluate the RHS unconditionally: the
    // RHS may revert (checked arithmetic), and Solidity short-circuits.
    if (e.op === '&&' || e.op === '||') {
      const left = this.lowerExpr(e.left, ctx, out);
      const t = this.fresh();
      const inner: string[] = [];
      const right = this.lowerExpr(e.right, ctx, inner);
      out.push(`let ${t} := ${e.op === '&&' ? '0' : '1'}`);
      out.push(`if ${e.op === '&&' ? left : `iszero(${left})`} {`);
      for (const s of inner) out.push('  ' + s);
      out.push(`  ${t} := ${right}`);
      out.push('}');
      return t;
    }

    // solc evaluates a binary operation's RIGHT operand before its LEFT operand. This is
    // invisible for side-effect-free operands but observable when an operand mutates state
    // (incDec / assignExpr in value position), e.g. `(++x) * 100 + (++x)` or `(x = v) + x`.
    // Evaluate the right operand first AND freeze it into a fresh temp: the freeze is what
    // makes the value stick when the right operand is a live variable read that the left
    // operand then mutates. The left operand is evaluated last and used immediately, so it
    // needs no snapshot. (&& / || above are short-circuit and stay left-first.)
    const rReg = this.lowerExpr(e.right, ctx, out);
    const r = this.fresh();
    out.push(`let ${r} := ${rReg}`);
    const l = this.lowerExpr(e.left, ctx, out);
    const opType = e.left.type; // operands are unified to the same type (except ** exponent)
    // exponentiation a ** b: checked (Panic 0x11 on overflow) or wrapping (unchecked).
    if (e.op === '**') {
      if (e.unchecked) return this.wrapToType(opType, `exp(${l}, ${r})`);
      return `${this.checkedExp(opType)}(${l}, ${r})`;
    }
    // unchecked + - * : wrap (mask/sign-extend) to the operand width, no overflow revert.
    if (e.unchecked && (e.op === '+' || e.op === '-' || e.op === '*')) {
      const raw = e.op === '+' ? `add(${l}, ${r})` : e.op === '-' ? `sub(${l}, ${r})` : `mul(${l}, ${r})`;
      return this.wrapToType(opType, raw);
    }
    // unchecked signed division: division-by-zero still Panics 0x12, but the lone signed
    // overflow (INT_MIN / -1) WRAPS to INT_MIN (EVM sdiv) instead of Panic 0x11, matching
    // solc's unchecked block. (unchecked uint div == checked: no overflow possible.)
    if (e.unchecked && e.op === '/' && opType.kind === 'int') {
      // re-normalize to the narrow width: INT_MIN/-1 wraps and the raw sdiv result
      // (e.g. +128 for int8) must be sign-extended back into range, like every other op.
      return this.wrapToType(opType, `${this.uncheckedDivInt()}(${l}, ${r})`);
    }
    switch (e.op) {
      case '+':
        return `${this.checkedArith('add', opType)}(${l}, ${r})`;
      case '-':
        return `${this.checkedArith('sub', opType)}(${l}, ${r})`;
      case '*':
        return `${this.checkedArith('mul', opType)}(${l}, ${r})`;
      case '/':
        return `${this.checkedArith('div', opType)}(${l}, ${r})`;
      case '%':
        return `${this.checkedArith('mod', opType)}(${l}, ${r})`;
      case '&':
        return `and(${l}, ${r})`;
      case '|':
        return `or(${l}, ${r})`;
      case '^':
        return `xor(${l}, ${r})`;
      case '<<': {
        const res = `shl(${r}, ${l})`;
        // narrow results must be re-normalized to their in-register form.
        if (opType.kind === 'uint' && opType.bits < 256) return `and(${res}, ${uintMaxHex(opType.bits)})`;
        if (opType.kind === 'int' && opType.bits < 256) return `signextend(${opType.bits / 8 - 1}, ${res})`;
        return res;
      }
      case '>>':
        if (opType.kind === 'int') return `sar(${r}, ${l})`;
        // bytesN >> n: shr leaks data bits into the low padding region; mask back to the high
        // `size` bytes so the result stays a canonical left-aligned bytesN (byte-identical to solc).
        if (opType.kind === 'bytesN' && opType.size < 32)
          return `and(shr(${r}, ${l}), ${bytesNHighMaskHex(opType.size)})`;
        return `shr(${r}, ${l})`;
      case '<':
        return opType.kind === 'int' ? `slt(${l}, ${r})` : `lt(${l}, ${r})`;
      case '>':
        return opType.kind === 'int' ? `sgt(${l}, ${r})` : `gt(${l}, ${r})`;
      case '<=':
        return `iszero(${opType.kind === 'int' ? `sgt(${l}, ${r})` : `gt(${l}, ${r})`})`;
      case '>=':
        return `iszero(${opType.kind === 'int' ? `slt(${l}, ${r})` : `lt(${l}, ${r})`})`;
      case '==':
        return `eq(${l}, ${r})`;
      case '!=':
        return `iszero(eq(${l}, ${r}))`;
    }
  }

  // ---- checked-arithmetic helpers -----------------------------------------

  private checkedArith(op: 'add' | 'sub' | 'mul' | 'div' | 'mod', t: JethType): string {
    if (t.kind === 'uint') {
      switch (op) {
        case 'add':
          return this.checkedAddUint(t.bits);
        case 'sub':
          return this.checkedSubUint(t.bits);
        case 'mul':
          return this.checkedMulUint(t.bits);
        case 'div':
          return this.checkedDivUint();
        case 'mod':
          return this.checkedModUint();
      }
    }
    if (t.kind === 'int') {
      switch (op) {
        case 'add':
          return this.checkedAddInt(t.bits);
        case 'sub':
          return this.checkedSubInt(t.bits);
        case 'mul':
          return this.checkedMulInt(t.bits);
        case 'div':
          return this.checkedDivInt(t.bits);
        case 'mod':
          return this.checkedModInt();
      }
    }
    throw new UnsupportedError(`arithmetic on type '${t.kind}' is not supported`);
  }

  /** Normalize an arithmetic result to a type's in-register form (mask uintN, sign-extend
   *  intN). A no-op for 256-bit. Used by unchecked (wrapping) arithmetic and shifts. */
  private wrapToType(t: JethType, expr: string): string {
    if (t.kind === 'uint') return t.bits === 256 ? expr : `and(${expr}, ${uintMaxHex(t.bits)})`;
    if (t.kind === 'int') return t.bits === 256 ? expr : `signextend(${t.bits / 8 - 1}, ${expr})`;
    return expr;
  }

  /** Checked exponentiation base ** exponent for an integer type (Panic 0x11 on overflow,
   *  Solidity-identical). Square-and-multiply with FULL-WIDTH (256-bit) checked muls for
   *  the intermediates, then a final range check against the result type. */
  private checkedExp(t: JethType): string {
    const name = `jeth_exp_${t.kind === 'int' ? 'i' : 'u'}${t.kind === 'uint' || t.kind === 'int' ? t.bits : 0}`;
    if (!this.helpers.has(name)) {
      const cmul = t.kind === 'int' ? this.checkedMulInt(256) : this.checkedMulUint(256);
      let rangeCheck = '';
      if (t.kind === 'uint' && t.bits < 256)
        rangeCheck = `if gt(power, ${uintMaxHex(t.bits)}) { ${this.panic()}(0x11) }`;
      if (t.kind === 'int' && t.bits < 256) {
        const max = toWord((1n << BigInt(t.bits - 1)) - 1n);
        const min = toWord(-(1n << BigInt(t.bits - 1)));
        rangeCheck = `if or(sgt(power, ${max}), slt(power, ${min})) { ${this.panic()}(0x11) }`;
      }
      this.helpers.set(
        name,
        `function ${name}(base, exponent) -> power {
  power := 1
  if exponent {
    for { } gt(exponent, 1) { } {
      if and(exponent, 1) { power := ${cmul}(power, base) }
      base := ${cmul}(base, base)
      exponent := shr(1, exponent)
    }
    power := ${cmul}(power, base)
  }
  ${rangeCheck}
}`,
      );
    }
    return name;
  }

  /** Unchecked signed division: Panic(0x12) on division by zero (NOT suppressed by
   *  unchecked), but the signed overflow INT_MIN/-1 wraps (sdiv) instead of Panic(0x11). */
  private uncheckedDivInt(): string {
    const name = 'jeth_unchecked_div_int';
    if (!this.helpers.has(name)) {
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {\n  if iszero(b) { ${this.panic()}(0x12) }\n  r := sdiv(a, b)\n}`,
      );
    }
    return name;
  }

  private panic(): string {
    this.helpers.set(
      'panic',
      `function panic(code) {
  mstore(0, shl(224, 0x4e487b71))
  mstore(4, code)
  revert(0, 0x24)
}`,
    );
    return 'panic';
  }

  private checkedAddUint(bits: number): string {
    const name = `checked_add_uint${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      const ov = bits === 256 ? `lt(r, a)` : `gt(r, ${uintMaxHex(bits)})`;
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  r := add(a, b)
  if ${ov} { panic(0x11) }
}`,
      );
    }
    return name;
  }
  private checkedSubUint(bits: number): string {
    const name = `checked_sub_uint${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  if gt(b, a) { panic(0x11) }
  r := sub(a, b)
}`,
      );
    }
    return name;
  }
  private checkedMulUint(bits: number): string {
    const name = `checked_mul_uint${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      const widthChk = bits === 256 ? '0' : `gt(r, ${uintMaxHex(bits)})`;
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  r := mul(a, b)
  if or(and(iszero(iszero(a)), iszero(eq(div(r, a), b))), ${widthChk}) { panic(0x11) }
}`,
      );
    }
    return name;
  }
  private checkedDivUint(): string {
    const name = `checked_div_uint`;
    if (!this.helpers.has(name)) {
      this.panic();
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  if iszero(b) { panic(0x12) }
  r := div(a, b)
}`,
      );
    }
    return name;
  }
  private checkedModUint(): string {
    const name = `checked_mod_uint`;
    if (!this.helpers.has(name)) {
      this.panic();
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  if iszero(b) { panic(0x12) }
  r := mod(a, b)
}`,
      );
    }
    return name;
  }

  private checkedAddInt(bits: number): string {
    const name = `checked_add_int${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      const { min, max } = intRange({ kind: 'int', bits });
      const chk =
        bits === 256
          ? `or(and(iszero(slt(b, 0)), slt(r, a)), and(slt(b, 0), sgt(r, a)))`
          : `or(sgt(r, ${toWord(max)}), slt(r, ${toWord(min)}))`;
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  r := add(a, b)
  if ${chk} { panic(0x11) }
}`,
      );
    }
    return name;
  }
  private checkedSubInt(bits: number): string {
    const name = `checked_sub_int${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      const { min, max } = intRange({ kind: 'int', bits });
      const chk =
        bits === 256
          ? `or(and(iszero(slt(b, 0)), sgt(r, a)), and(slt(b, 0), slt(r, a)))`
          : `or(sgt(r, ${toWord(max)}), slt(r, ${toWord(min)}))`;
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  r := sub(a, b)
  if ${chk} { panic(0x11) }
}`,
      );
    }
    return name;
  }
  private checkedMulInt(bits: number): string {
    const name = `checked_mul_int${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      const { min, max } = intRange({ kind: 'int', bits });
      const widthChk = bits === 256 ? '' : ` if or(sgt(r, ${toWord(max)}), slt(r, ${toWord(min)})) { panic(0x11) }`;
      const minHex = toWord(min);
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  r := mul(a, b)
  if iszero(iszero(a)) {
    if iszero(eq(sdiv(r, a), b)) { panic(0x11) }
  }
  if and(eq(a, ${toWord(-1n)}), eq(b, ${minHex})) { panic(0x11) }${widthChk}
}`,
      );
    }
    return name;
  }
  private checkedDivInt(bits: number): string {
    const name = `checked_div_int${bits}`;
    if (!this.helpers.has(name)) {
      this.panic();
      const { min } = intRange({ kind: 'int', bits });
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  if iszero(b) { panic(0x12) }
  if and(eq(a, ${toWord(min)}), eq(b, ${toWord(-1n)})) { panic(0x11) }
  r := sdiv(a, b)
}`,
      );
    }
    return name;
  }
  private checkedModInt(): string {
    const name = `checked_mod_int`;
    if (!this.helpers.has(name)) {
      this.panic();
      this.helpers.set(
        name,
        `function ${name}(a, b) -> r {
  if iszero(b) { panic(0x12) }
  r := smod(a, b)
}`,
      );
    }
    return name;
  }

  private fresh(): string {
    return `_t${this.tmp++}`;
  }

  // ---- lowering scope stack (mirrors the analyzer; unique Yul names) --------

  private freshLocal(jethName: string): string {
    return `v_${jethName}_${this.nameCounter++}`;
  }
  private ctxPush(ctx: LowerCtx): void {
    ctx.scopes.push(new Map());
  }
  private ctxPop(ctx: LowerCtx): void {
    ctx.scopes.pop();
  }
  private ctxDeclare(ctx: LowerCtx, jethName: string, yulName: string): void {
    ctx.scopes[ctx.scopes.length - 1]!.set(jethName, yulName);
  }
  private ctxLookup(ctx: LowerCtx, jethName: string): string {
    for (let i = ctx.scopes.length - 1; i >= 0; i--) {
      const n = ctx.scopes[i]!.get(jethName);
      if (n) return n;
    }
    throw new UnsupportedError(`read of unbound local ${jethName}`);
  }
}

interface LowerCtx {
  scopes: Map<string, string>[]; // jeth name -> unique yul name, innermost last
  returnType: JethType;
  dynParams: Map<string, { dataPtr: string; len: string }>; // calldata bytes/string params
  cdArrays: Map<string, { offset: string; length: string; elem: JethType }>; // calldata array params
  cdAggregates: Map<string, { baseOffset: number; type: JethType }>; // struct / fixed-array params (inline calldata head)
  cdDynStructs: Map<string, { tupleStart: string; type: JethType }>; // dynamic struct params (runtime tuple-start byte ptr)
  cdParamHead: Map<string, { head: number; type: JethType }>; // calldata head byte of EVERY param (for whole-param echo via the recursive encoder)
  fnMode?: { retVar: string | null; retVars?: string[] }; // set when lowering an INTERNAL function body: `return` -> retVar:=v; leave (retVar null = void). retVars set for a multi-value return.
  specialEntry?: boolean; // Phase 6: lowering a @receive/@fallback body INLINE in the dispatcher; a bare `return;` -> stop() (matches solc).
  immStaged?: Map<string, string>; // Phase 5: @immutable name -> its staged-shadow Yul var (constructor body only)
  // Phase 5 ctor-reachable-immutable-read fix: @immutable name -> a reserved CREATION-block memory cell
  // holding its staged value. solc forbids loadimmutable + setimmutable of one immutable in a single
  // assembly subroutine, so a helper reachable from the constructor (a Yul function in the creation
  // block, which cannot close over jeth_constructor's staged ret-vars) reads the staged value from this
  // memory cell instead of loadimmutable, and the staged write mirrors each assignment into the cell.
  // Set on the ctor body's ctx AND on each ctor-reachable helper copy's ctx; absent everywhere else.
  ctorImmShadow?: Map<string, string>;
  // Phase 5 (full modifiers): set ONLY while lowering a function's modifierWrap in its dispatch case.
  // The {modifierBody} marker lowers to a call of the synthesized body function (userfn) with the
  // materialized args, capturing the result(s) into the buffered `retVars`. retVars is [] for a void
  // function, [r] for a single value/bytes/string/aggregate return (r holds the value or the memory
  // pointer), or [r0,r1,...] for a multi-value return. `returnType`/`returnTypes` describe how to
  // encode those buffered vars ONCE - reused both for the dispatch's final encode and for an early
  // `return;` inside the modifier body (JETH325), which encodes the CURRENT buffered vars and returns.
  modifierDispatch?: {
    userFn: string;
    args: string[];
    retVars: string[];
    returnType: JethType;
    returnTypes?: JethType[];
  };
}

// A lowered array reference, by source location.
type ArrayRef =
  | { src: 'storage'; lenSlot: string; elem: JethType } // dynamic T[] (data at keccak(lenSlot))
  | { src: 'calldata'; offset: string; length: string; elem: JethType }
  | { src: 'fixed'; baseSlot: bigint; length: number; elem: JethType } // Arr<T,N> inline
  | { src: 'memory'; ptr: string; elem: JethType; fixedLen?: number; staticElem?: boolean }; // memory T[] (ptr -> [len][elem0]...); fixedLen = FIXED outer (no [len] header, bound vs constant); staticElem = the element is an inline sub-image (vs an absolute pointer)

// The value source for a tuple (dynamic struct) being encoded: a constructed
// value (structNew args) or a calldata echo (the bound tuple-start byte ptr).
type TupleSrc =
  | { kind: 'new'; fields: StructField[]; args: Expr[] }
  | { kind: 'cd'; base: string }
  | { kind: 'mem'; headPtr: string }; // a memory dynamic-struct local (one word per field: value inline, bytes/string a pointer)

// W7A: one prepared component of a two-phase ABI-encode consumer (abi.encode* / event data /
// custom-error payload). `word` = a value spilled at its source position; `inline` = a static
// aggregate's flat image pointer (mcopy'd into the head at serialize time); `{mp,len}` = a
// bytes/string [len][data] pointer; `{mp,size}` = a self-contained ABI tail blob.
type EncPart =
  | { word: string }
  | { inline: true; mp: string; words: number }
  | { mp: string; len: string }
  | { mp: string; size: string };

// A lowered dynamic bytes/string value, by source location.
type DynRef =
  | { src: 'storage'; slot: string }
  | { src: 'calldata'; dataPtr: string; len: string }
  | { src: 'memory'; ptr: string; tailBytes?: string }; // ptr -> [len][data...]; tailBytes = full image byte size for a struct-element array

// ---- W7B: two-phase storage struct/array-literal writes ------------------------------------
// Phase 1 (prepare*) evaluates every RHS argument at its source position and captures a
// store-ready handle; phase 2 (emitPrepared*) performs all the storage writes. solc materializes
// the constructed value BEFORE touching storage, so a self-reading argument sees the OLD data.
/** A prepared ctor field argument: the handle feeds the matching store codec in phase 2. */
type PreparedFieldArg =
  | { k: 'ctor'; fields: StructField[]; items: PreparedFieldArg[] } // nested constructor
  | { k: 'dynStruct'; ptr: string } // pointer-headed dyn-struct image -> writeDynStructFromMem
  | { k: 'dynArr'; elem: JethType; ptr: string; agg: boolean } // memory array image -> copyMem(Agg)ArrayIntoStorage
  | { k: 'dynLeafFixed'; ptr: string } // N-pointer fixed image -> storeDynLeafFixedArrayFromMem
  | { k: 'lit'; lit: Expr & { kind: 'arrayLit' }; items: PreparedLitElem[] } // fixed-array literal
  | { k: 'staticAgg'; ptr: string } // flat ABI image -> storeStaticAggFromMem
  | { k: 'bytes'; ref: DynRef } // memory bytes ref -> storeDynamic
  | { k: 'value'; reg: string }; // frozen value word -> storeState

/** A prepared fixed-array-literal element (value / nested literal / struct ctor). */
type PreparedLitElem =
  | { k: 'value'; reg: string }
  | { k: 'ctor'; fields: StructField[]; items: PreparedFieldArg[] }
  | { k: 'lit'; lit: Expr & { kind: 'arrayLit' }; items: PreparedLitElem[] };

/** A prepared whole-struct RHS (the storeStructTo family). */
type PreparedStructStore =
  | { k: 'ctor'; fields: StructField[]; items: PreparedFieldArg[] }
  | { k: 'memStatic'; ptr: string }
  | { k: 'memDyn'; ptr: string }
  | { k: 'storageCopy'; srcSlot: string };

const TOP_BYTE = '0xff00000000000000000000000000000000000000000000000000000000000000';

function indent(text: string, spaces: number): string {
  const pad = ' '.repeat(spaces);
  return text
    .split('\n')
    .map((l) => (l.length ? pad + l : l))
    .join('\n');
}

export function emitYul(contract: ContractIR): string {
  return new YulEmitter().emit(contract);
}

/** Phase B: emit the standalone Yul source for ONE external (delegatecall) library object (compiled
 *  to its own bytecode and linked into the contract at deploy time). A fresh YulEmitter per library
 *  keeps each object's helper/scope state independent. */
export function emitLibraryYul(lib: LibraryIR): string {
  return new YulEmitter().emitLibraryObject(lib);
}
