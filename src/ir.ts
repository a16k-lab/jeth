// Typed intermediate representation. The semantic analyzer + type checker produce
// this; the Yul lowerer consumes it. Every expression carries its resolved JethType.
import type { JethType, StructField } from './types.js';

export interface StructDecl {
  name: string;
  fields: StructField[];
  slotCount: number;
}

export type Visibility = 'external' | 'public' | 'internal' | 'private';
export type Mutability = 'pure' | 'view' | 'nonpayable' | 'payable';

export type BinOp =
  | '+'
  | '-'
  | '*'
  | '**'
  | '/'
  | '%'
  | '<'
  | '>'
  | '<='
  | '>='
  | '=='
  | '!='
  | '&'
  | '|'
  | '^'
  | '<<'
  | '>>'
  | '&&'
  | '||';

export type UnOp = '-' | '!' | '~';

// EVM execution-environment globals. Each lowers to its Yul builtin `op()`,
// except 'msgsig' (a calldata mask). 'callvalue' (msg.value) requires @payable;
// the env ops are forbidden in @pure; 'msgsig' is allowed even in @pure.
export type GlobalOp =
  | 'caller' // msg.sender
  | 'callvalue' // msg.value (payable-only)
  | 'origin' // tx.origin
  | 'gasprice' // tx.gasprice
  | 'blobbasefee' // block.blobbasefee (EIP-4844 cancun, BLOBBASEFEE 0x4a)
  | 'address' // address(this)
  | 'timestamp'
  | 'number'
  | 'chainid'
  | 'coinbase'
  | 'basefee'
  | 'gaslimit'
  | 'prevrandao'
  | 'gas' // gasleft()
  | 'msgsig'; // msg.sig

export type Expr =
  // hexBytes: when the literal was written as a HEX number (0x...), the source byte width
  // (hex digits / 2). solc converts a hex literal to bytesN iff hexBytes === N. undefined for
  // decimal literals and for synthesized literals.
  | { kind: 'literalInt'; type: JethType; value: bigint; hexBytes?: number }
  | { kind: 'literalBool'; type: JethType; value: boolean }
  | { kind: 'rawReg'; type: JethType; reg: string } // a pre-computed Yul register (internal; used to feed a value into the assign lowering, e.g. tuple destructuring)
  | { kind: 'stateRead'; type: JethType; slot: bigint; offset: number; varName: string }
  // Phase 5 immutables: a runtime read lowers to loadimmutable("name") (baked into code, no slot);
  // a read INSIDE the constructor body reads the staged shadow (the value assigned so far).
  | { kind: 'immutableRead'; type: JethType; name: string }
  | { kind: 'immutableStagedRead'; type: JethType; name: string }
  | { kind: 'localRead'; type: JethType; name: string }
  | { kind: 'binary'; type: JethType; op: BinOp; left: Expr; right: Expr; unchecked: boolean }
  | { kind: 'ternary'; type: JethType; cond: Expr; then: Expr; else: Expr } // c ? a : b (short-circuit)
  | {
      kind: 'incDec';
      type: JethType;
      target: LValue;
      readExpr: Expr;
      isInc: boolean;
      prefix: boolean;
      unchecked: boolean;
    } // x++ / ++x in value position
  | { kind: 'assignExpr'; type: JethType; target: LValue; value: Expr } // (x = v)/(x += v) in value position: stores value, yields it
  | { kind: 'call'; type: JethType; fn: string; args: Expr[] } // internal/private function call f(args) yielding a value
  | { kind: 'cdAggregateValue'; type: JethType; param: string } // whole STATIC struct / fixed-array calldata param echo (return a)
  | { kind: 'unary'; type: JethType; op: UnOp; operand: Expr; unchecked: boolean }
  // --- Phase 3 ---
  | { kind: 'global'; type: JethType; op: GlobalOp } // msg.*/block.*/tx.*/address(this)
  | { kind: 'cast'; type: JethType; from: JethType; operand: Expr } // address/uint160/bytes20 conversions
  | {
      kind: 'mapGet'; // this.m[k]...[k] read
      type: JethType; // final value type
      baseSlot: bigint;
      keys: Expr[]; // outer-to-inner
      keyTypes: JethType[];
    }
  // --- Phase 4: dynamic bytes/string values (references, not 256-bit words) ---
  | { kind: 'dynStateRead'; type: JethType; slot: bigint } // this.s (storage)
  | { kind: 'dynParamRead'; type: JethType; name: string } // calldata param (codegen binds ptr/len)
  | { kind: 'msgData'; type: JethType } // msg.data: a calldata bytes view over the WHOLE calldata [0, calldatasize())
  // <calldata bytes>.slice(start[, end]) -> a zero-copy calldata bytes sub-view (solc data[start:end]).
  // end defaults to the base length; lowering reverts EMPTY iff !(start <= end <= baseLen).
  | { kind: 'calldataSlice'; type: JethType; base: Expr; start: Expr; end?: Expr }
  | { kind: 'dynLocalRead'; type: JethType; name: string } // bytes/string MEMORY local (register holds a [len][data] pointer)
  | { kind: 'stringLiteral'; type: JethType; bytes: Uint8Array } // a memory bytes/string literal
  | { kind: 'dynLength'; type: JethType; operand: Expr } // s.length -> u256
  | { kind: 'keccak'; type: JethType; arg: Expr } // keccak256(bytes/string) -> bytes32
  | { kind: 'precompileHash'; type: JethType; arg: Expr; addr: number; leftShift: number } // sha256(0x02)->bytes32 / ripemd160(0x03)->bytes20
  | { kind: 'modOp'; type: JethType; op: 'addmod' | 'mulmod'; a: Expr; b: Expr; m: Expr } // addmod/mulmod -> u256
  // ecrecover(hash, v, r, s) -> address: the RAW unsafe builtin (= solc ecrecover, staticcall 0x01).
  // address(0) on any failure, NEVER reverts, NO malleability check (the returndatasize()==0x20 guard).
  | { kind: 'ecrecover'; type: JethType; hash: Expr; v: Expr; r: Expr; s: Expr }
  // recover(hash, sig) / recover(hash, v, r, s) -> address: the SAFE OZ-5.x ECDSA form. `sig` present =>
  // the 65-byte bytes overload (length!=65 -> ECDSAInvalidSignatureLength); else the split form (no length
  // check). Both check s>HALF_ORDER (STRICT) -> ECDSAInvalidSignatureS, signer==0 -> ECDSAInvalidSignature.
  | { kind: 'recover'; type: JethType; hash: Expr; sig?: Expr; v?: Expr; r?: Expr; s?: Expr }
  // modexp(base, exp, mod) -> bytes (length == mod.length): arbitrary-precision modexp, staticcall 0x05.
  | { kind: 'modexp'; type: JethType; base: Expr; exp: Expr; mod: Expr }
  // bn256Add/Mul/Pairing: alt_bn128 precompiles 0x06/0x07/0x08. add/mul yield a fresh 2-word memory G1Point
  // image (memAggregate-shaped); pairing yields a bool. Reverts EMPTY on an invalid point / bad length.
  | {
      kind: 'bn256';
      type: JethType;
      op: 'add' | 'mul' | 'pairing';
      addr: number;
      args: Expr[];
      insize: number | 'dynamic';
      outsize: number;
    }
  // blake2f(rounds, h(64), m(128), t:bytes16, f:bool) -> 64-byte bytes: BLAKE2b compression, staticcall 0x09.
  | { kind: 'blake2f'; type: JethType; rounds: Expr; h: Expr; m: Expr; t: Expr; f: Expr }
  | { kind: 'abiEncode'; type: JethType; packed: boolean; args: Expr[]; selector?: Expr; sig?: Expr } // abi.encode/encodePacked/encodeWithSelector(selector)/encodeWithSignature(sig) -> bytes
  // abi.decode(data, T) / data.decode(T) -> the single decoded value of type T (memory-sourced ABI decode
  // of the [len][data] bytes value `data`). The tuple form abi.decode(data, [T1, ...]) is a DestructureSource
  // (see below). A value-type result is one word (lowered via lowerExpr); a bytes/string/array/struct result
  // is a memory image pointer (lowered via lowerDynamic / aggArgToMemPtr). Malformed input reverts like solc:
  // Panic(0x41) on an oversized length / memory-alloc cap, empty revert on an out-of-bounds offset/length.
  | { kind: 'abiDecode'; type: JethType; data: Expr }
  | { kind: 'blockhash'; type: JethType; arg: Expr } // blockhash(uint) -> bytes32
  | { kind: 'blobhash'; type: JethType; arg: Expr } // blobhash(uint) -> bytes32 (EIP-4844)
  | { kind: 'balance'; type: JethType; addr: Expr } // <address>.balance -> u256
  // --- Phase 1 proxies: EIP-1167 minimal-proxy (OZ Clones 5.1) ---
  // isContract(addr) -> bool: gt(extcodesize(addr), 0) (OZ `addr.code.length > 0`). A pure code read.
  | { kind: 'isContract'; type: JethType; addr: Expr }
  // clone*/cloneWithArgs*/cloneDeterministic*: deploy an EIP-1167 clone of `impl` via CREATE (salt
  // unset) or CREATE2 (salt set). `args` (bytes) present => the OZ 5.1 cloneWithImmutableArgs modified
  // init that returns runtime+args. Lowers to the EXACT canonical creation code + create/create2; a zero
  // result reverts EMPTY. State-mutating (CREATE) -> requires a nonpayable/@payable caller. -> address.
  | { kind: 'cloneDeploy'; type: JethType; impl: Expr; salt?: Expr; args?: Expr }
  // predictClone(impl, salt) / predictCloneWithArgs(impl, salt, args) -> address: the CREATE2 address
  // keccak256(0xff ++ address(this) ++ salt ++ keccak256(creationCode))[12:] over the EXACT creation
  // code clone* would deploy. A pure read of address(this); does not mutate state.
  | { kind: 'predictClone'; type: JethType; impl: Expr; salt: Expr; args?: Expr }
  // cloneArgs() -> bytes: THIS clone's appended immutable args (OZ Clones.fetchCloneArgs(address(this)) =
  // own code[0x2d:], via extcodecopy(address(), dst, 0x2d, extcodesize(address())-0x2d)). A code read.
  | { kind: 'cloneArgs'; type: JethType }
  // --- Phase 2a proxies: EIP-1967 upgradeable-proxy foundation (byte-identical to OZ ERC1967) ---
  // proxyInit(impl, [admin,] initData): the @proxy constructor primitive. require(isContract(impl)); write
  // the EIP-1967 impl slot; (admin form) write the EIP-1967 admin slot; emit Upgraded(impl); if
  // initData.length>0 delegatecall(impl, initData) and BUBBLE its revert verbatim. STATE-MUTATING.
  | { kind: 'proxyInit'; type: JethType; impl: Expr; admin?: Expr; initData: Expr }
  // upgradeProxy(newImpl, data): require(isContract(newImpl)); write the EIP-1967 impl slot; emit
  // Upgraded(newImpl); if data.length>0 delegatecall(newImpl, data) + bubble. The USER gates who may call
  // it (e.g. require(msg.sender == proxyAdmin())). STATE-MUTATING. -> void.
  | { kind: 'upgradeProxy'; type: JethType; impl: Expr; data: Expr }
  // proxyImplementation() / proxyAdmin() -> address: SLOAD the EIP-1967 impl / admin slot. A storage read.
  | { kind: 'proxySlotRead'; type: JethType; slot: 'impl' | 'admin' }
  // --- Phase 2d proxies: the BEACON proxy variant (byte-identical to OZ BeaconProxy 5.x) ---
  // proxyInitBeacon(beacon, initData): the @proxy('beacon') constructor primitive. require(isContract(beacon));
  // write the EIP-1967 BEACON slot; emit BeaconUpgraded(beacon); if initData.length>0 fetch the current impl
  // via the beacon's implementation() staticcall, then delegatecall(impl, initData) and BUBBLE its revert.
  // STATE-MUTATING.
  | { kind: 'proxyInitBeacon'; type: JethType; beacon: Expr; initData: Expr }
  // proxyBeacon() -> address: SLOAD the EIP-1967 beacon slot. A storage read (view-ok, pure-reject).
  | { kind: 'proxyBeaconRead'; type: JethType }
  // --- Phase 3 DIAMOND: synthesis-only builtins (emitted by the @diamond expansion, src/diamond.ts) ---
  // diamondInit(owner): sstore contractOwner, register the 4 ERC-165 ids, emit OwnershipTransferred(0,owner)
  | { kind: 'diamondInit'; type: JethType; owner: Expr }
  // initializeDiamondCut's _init delegatecall: if init==0 return; require code; delegatecall + bubble revert
  | { kind: 'diamondDelegateInit'; type: JethType; init: Expr; data: Expr }
  // the facets() loupe: build a Facet[] (address + bytes4[]) from the split diamond-3 storage (raw Yul)
  | { kind: 'diamondFacets'; type: JethType }
  // --- Phase 3 DIAMOND (packed / diamond-2 layout): synthesis-only builtins for the @diamond('packed') model ---
  // __diamondCutPacked(): void; the whole diamond-2 add/replace/remove loop (reads _diamondCut from calldata,
  // packs 8 selectors/slot, CLEAR_ADDRESS_MASK/CLEAR_SELECTOR_MASK + swap-into-gap removal) in raw Yul.
  | { kind: 'diamondCutPacked'; type: JethType }
  // The four diamond-2 loupe reconstructors (rebuild facet grouping in memory from the packed selectorSlots).
  | { kind: 'diamondFacetsPacked'; type: JethType } // facets() -> Facet[]
  | { kind: 'diamondFacetSelectorsPacked'; type: JethType; facet: Expr } // facetFunctionSelectors(addr) -> bytes4[]
  | { kind: 'diamondFacetAddressesPacked'; type: JethType } // facetAddresses() -> address[]
  // --- Phase 3 DIAMOND (solidstate / v0.0.61): synthesis-only builtins for the @diamond('solidstate') model ---
  // diamondInitSolidstate(owner): sstore owner (Ownable namespace), register solidstate's ERC-165 ids
  // (ERC165Base namespace), emit OwnershipTransferred(0, owner).
  | { kind: 'diamondInitSolidstate'; type: JethType; owner: Expr }
  // __diamondCutSolidstate(): the solidstate diamond-2 add/replace/remove loop (same packing as the packed
  // model, but solidstate's custom-error revert set + require order).
  | { kind: 'diamondCutSolidstate'; type: JethType }
  // __revertSelector(sel): revert with a bare 4-byte custom-error selector (no ABI args) - byte-identical
  // to solc's `revert SomeError()`.
  | { kind: 'revertSelector'; type: JethType; selector: bigint }
  // --- Phase 6: external low-level calls ---
  // <addr>.code -> bytes (EXTCODESIZE + EXTCODECOPY); <addr>.codehash -> bytes32 (EXTCODEHASH)
  | { kind: 'extCode'; type: JethType; addr: Expr; member: 'code' | 'codehash' }
  // Scoped markers usable ONLY inside an extCall success condition: `this.ok` -> the CALL success bool,
  // `this.data` -> the returndata bytes. The yul backend binds them to the call's captured registers
  // while lowering the checks (callData is a bytes reference, resolved via lowerDynamic).
  | { kind: 'callOk'; type: JethType }
  | { kind: 'callData'; type: JethType }
  // Scoped markers usable ONLY inside a try/catch CATCH body: `this.reason` -> the SOFT-decoded
  // Error(string) message (or "" when the revert bytes are not a well-formed Error(string)); `this.panic`
  // -> the decoded Panic(uint256) code (or 0). The yul backend binds the catch returndata blob to
  // EXT_CALL_DATA_BINDING while lowering the catch body, then computes these from it.
  | { kind: 'catchReason'; type: JethType } // -> string (the decoded Error(string), soft)
  | { kind: 'catchPanic'; type: JethType } // -> u256 (the decoded Panic code, soft)
  // <addr>.call/staticcall({ data, value?, gas?, success }) -> bytes (returndata). Performs the
  // CALL/STATICCALL binding ok+data, evaluates the ordered success checks (first failing one reverts
  // with its reason), and yields the returndata bytes. <addr>.tryCall/tryStaticcall({...}) (checks
  // empty) is lowered via DestructureSource 'extCall' instead; this Expr form is the bytes value.
  // `bubble`: on failure (iszero(ok)), revert with the captured returndata VERBATIM (high-level typed
  // interface calls re-throw the callee's exact revert bytes). `codeGuard`: after the failure bubble,
  // `if iszero(extcodesize(addr)) { revert(0,0) }` (a high-level call to an EOA / non-contract reverts
  // empty). Both default false so the low-level addr.call path (success checks) is unchanged.
  | {
      kind: 'extCall';
      type: JethType;
      op: 'call' | 'staticcall' | 'delegatecall';
      // For op 'call'/'staticcall' the target is a runtime address (`addr`). For op 'delegatecall'
      // (Phase B external libraries) the target is a LINK-TIME library address: `addr` is omitted and
      // `lib` names the library, lowered to `linkersymbol("<lib>")` (solc emits the `__$..$__`
      // placeholder + a linkReference). A delegatecall has NO addr/value/gas operands.
      addr?: Expr;
      lib?: string;
      data: Expr;
      value?: Expr;
      gas?: Expr;
      checks: SuccessCheck[];
      bubble?: boolean;
      codeGuard?: boolean;
    }
  | { kind: 'byteIndex'; type: JethType; base: Expr; index: Expr } // b[i] -> bytes1
  // --- Phase 4: dynamic arrays T[] ---
  | { kind: 'arrayLen'; type: JethType; arr: ArrayExpr } // a.length -> u256
  | { kind: 'arrayGet'; type: JethType; arr: ArrayExpr; index: Expr; oobEmpty?: boolean } // a[i] read (bounds-checked; oobEmpty: revert(0,0) instead of Panic 0x32, for @public getters)
  | { kind: 'arrayValue'; type: JethType; arr: ArrayExpr } // a whole array (for return encoding)
  | { kind: 'arrayLit'; type: JethType; elem: JethType; elements: Expr[] } // [a,b,c] -> memory T[]
  | { kind: 'newArray'; type: JethType; elem: JethType; length: Expr } // new T[](n) -> zeroed memory T[]
  // --- Phase 4c: structs ---
  | { kind: 'structNew'; type: JethType; fields: StructField[]; args: Expr[] } // Point(a, b)
  | { kind: 'structValue'; type: JethType; baseSlot: bigint } // whole storage struct (for return)
  | { kind: 'memField'; type: JethType; local: string; wordOffset: number } // read a value field/element of a memory-aggregate local (p.x)
  | { kind: 'aggFieldRead'; type: JethType; base: Expr; wordOffset: number } // read a VALUE field of a struct-valued Expr base (e.g. this.mk(a).x) - materialize base to a memory pointer, mload at the offset
  | { kind: 'memElem'; type: JethType; local: string; index: Expr; length: number; wordOffset?: number } // a[i] on a fixed-array memory local (value element, bounds-checked); wordOffset: a fixed-array FIELD of a memory struct (p.a[i]) starts that many words into the image
  | { kind: 'memAggregate'; type: JethType; local: string; wordOffset?: number } // a whole memory aggregate, or a nested struct field at wordOffset (sub-pointer into the parent image)
  | { kind: 'memDynStructValue'; type: JethType; local: string } // a whole DYNAMIC-field struct memory local (head: value fields inline, bytes/string fields as pointers)
  | { kind: 'memDynField'; type: JethType; local: string; wordOffset: number } // a bytes/string field of a memory dynamic struct (the head word holds the [len][data] pointer)
  | { kind: 'structArrayElem'; type: JethType; arr: ArrayExpr; index: Expr } // whole storage/fixed/mapping struct element this.recs[i] (for return / copy source)
  | { kind: 'mapStorageValue'; type: JethType; baseSlot: bigint; keys: Expr[]; keyTypes: JethType[] } // return this.m[k] (whole struct/array mapping value)
  | { kind: 'mapDynValue'; type: JethType; baseSlot: bigint; keys: Expr[]; keyTypes: JethType[] } // this.m[k] where the value is bytes/string (dynamic value at the mapping slot)
  // --- Phase 4c-3: nested storage access (this.s.f, this.pts[i].x, this.m[k].f, this.m[r][c]) ---
  | { kind: 'placeRead'; type: JethType; path: AccessPath }
  // --- storage / mapping-valued DYNAMIC STRUCT bytes/string field (this.d.s,
  //     this.recs[i].s, this.m[k].s): the field header lives at the struct base
  //     slot + the field's slot offset (a normal storage bytes/string). Codegen
  //     folds the AccessPath to that slot, then reuses the storage bytes/string
  //     codec (loadStr / storeStrMem / strLen / strByteAt). ---
  | { kind: 'dynPlaceRead'; type: JethType; path: AccessPath }
  // --- Phase 4d: aggregate calldata params (struct / fixed-array field+index reads) ---
  | { kind: 'cdPlaceRead'; type: JethType; place: CalldataPlace }
  // --- Phase 4e-1: dynamic array of static struct (calldata param) field read ---
  | {
      kind: 'cdArrayField';
      type: JethType;
      arr: ArrayExpr;
      index: Expr;
      headWords: number;
      fieldType: JethType;
      elemIndex?: Expr;
      elemLength?: number;
    }
  // whole struct element of a calldata struct array (return ps[i]); the element is copied
  // from its (contiguous for a static struct / offset-located for a dynamic struct) calldata
  // head into a fresh ABI return blob, with the same bounds-check (Panic 0x32) as ps[i].field.
  | { kind: 'cdStructArrayElem'; type: JethType; arr: ArrayExpr; index: Expr }
  // --- Phase 4e-4: string[] / bytes[] (calldata param) element read -> a dynamic value ---
  | { kind: 'cdDynArrayElem'; type: JethType; arr: ArrayExpr; index: Expr }
  // --- storage / mapping-valued string[] / bytes[] element -> a dynamic value ---
  // (read this.ss[i] / this.m[k][i]; the element header lives at keccak(lenSlot)+i,
  //  a normal storage bytes/string; bounds-checked against the array length).
  | { kind: 'strArrayElem'; type: JethType; arr: ArrayExpr; index: Expr; oobEmpty?: boolean }
  // --- Phase 4e-6: dynamic struct (tuple with >=1 dynamic field) calldata param ---
  // Read a STATIC leaf reached by navigating a dynamic-struct field chain. The
  // codegen folds the path to a calldata byte offset (runtime tuple-start base).
  | { kind: 'cdDynStructLeaf'; type: JethType; place: CdDynPlace }
  // Read the DYNAMIC field (string/bytes) of a dynamic struct as a dynamic value
  // (re-encoded as a standalone top-level value on return, or .length / [i]).
  | { kind: 'cdDynStructField'; type: JethType; place: CdDynPlace }
  // The whole dynamic struct param (for `return d` echo). Codegen re-encodes it.
  // `place` (when set) targets a nested STRUCT field of a dynamic-struct param
  // (return o.inner): the encoder resolves that field's tuple-start base via the
  // navigator and re-encodes it as a standalone tuple (param is then unused).
  | { kind: 'cdDynStructValue'; type: JethType; param: string; place?: CdDynPlace };

/** A storage location reached by navigating a chain of field/index/key steps from
 *  a root state variable. Resolves at codegen to a (slot expr, byte offset). */
export interface AccessPath {
  baseSlot: bigint;
  steps: AccessStep[];
  oobEmpty?: boolean; // index/dynIndex out-of-bounds reverts EMPTY (revert(0,0)) instead of Panic 0x32
  // (for @public auto-getters, whose array-element access matches solc's empty-revert on OOB).
}
export type AccessStep =
  | { kind: 'field'; fieldSlot: number; fieldOffset: number; fieldType: JethType } // struct field
  | { kind: 'index'; index: Expr; strideSlots: number; length: number; elemType: JethType } // fixed-array element (whole-slot)
  | { kind: 'packedIndex'; index: Expr; perSlot: number; size: number; length: number; elemType: JethType } // packed fixed-array element (perSlot per slot, runtime byte offset)
  | { kind: 'dynIndex'; index: Expr; strideSlots: number; elemType: JethType } // dynamic T[] element (data at keccak(lenSlot), runtime bound)
  | { kind: 'packedDynIndex'; index: Expr; perSlot: number; size: number; elemType: JethType } // packed dynamic T[] element (data at keccak(lenSlot), runtime byte offset)
  | { kind: 'mapKey'; key: Expr; valueType: JethType }; // mapping key

/** A calldata location reached by navigating a chain of field/index steps from an
 *  aggregate (struct / fixed-array) function parameter. ABI head is UNPACKED (one
 *  32-byte word per leaf), so steps carry ABI head-word offsets, not storage slots.
 *  Resolves at codegen to a calldata byte offset; the leaf is read + validated. */
export interface CalldataPlace {
  param: string;
  steps: CdStep[];
  finalType: JethType;
}
export type CdStep =
  | { kind: 'field'; headWords: number; fieldType: JethType } // const head-word offset within a struct
  | { kind: 'index'; index: Expr; strideWords: number; length: number; elemType: JethType }; // fixed-array element

/** A navigation into a DYNAMIC struct calldata parameter (Phase 4e-6). The base
 *  resets to the tuple-start at every dynamic-struct boundary (spec section 3.2).
 *  Each step names a struct field by its ABI head-word offset within the *current*
 *  tuple (counting each preceding field as abiHeadWords words, dynamic fields as 1
 *  offset word). `crossDynamic` marks a field whose own value is itself dynamic
 *  (a nested dynamic struct or the terminal dynamic field): codegen reads its
 *  offset word at base+headWords*32, then resets base to base+offset. The final
 *  step's `fieldType` is the leaf/dynamic-field type. */
export interface CdDynPlace {
  param: string; // the top-level dynamic-struct param name (when arrayRoot is unset)
  steps: CdDynStep[];
  // when set, the base tuple is the i-th element of a D[] (dynamic-struct array): its
  // tuple start is resolved at codegen via the array's per-element offset table.
  arrayRoot?: { arr: ArrayExpr; index: Expr };
}
export interface CdDynStep {
  headWords: number; // ABI head-word offset of this field within the current tuple
  fieldType: JethType; // this field's type
  crossDynamic: boolean; // true iff this field's value is itself dynamic (offset word -> base reset)
}

/** A storage/calldata array reference (dynamic T[] or fixed Arr<T,N>). */
export interface ArrayExpr {
  base:
    | { kind: 'stateArray'; slot: bigint } // dynamic T[] state var (length at slot)
    | { kind: 'calldataArray'; name: string } // dynamic T[] calldata param
    | { kind: 'fixedArray'; baseSlot: bigint; length: number } // fixed Arr<T,N> (inline at baseSlot)
    | { kind: 'mapArray'; baseSlot: bigint; keys: Expr[]; keyTypes: JethType[] } // dynamic T[] mapping value (length at keccak(key.baseSlot))
    // --- Phase 4e-5 / 4e-8: an inner array reached by navigating a chain of index
    //     steps into a nested dynamic array (T[][], T[][][], string[][], ...). Each
    //     index descends one dynamic-array level via that container's inner-offset
    //     table (base = the word after the level's length word). `indices` lists the
    //     steps outer-to-inner (>=1); the resolved array's element type is `elem`. ---
    | { kind: 'cdNestedElem'; name: string; indices: Expr[] } // m[i], m[i][j], ... (calldata param)
    | { kind: 'cdSubElem'; name: string; index: Expr } // a[i] inner array of a MIXED calldata composite: dynamic-of-fixed (Arr<T,N>[]) or fixed-of-dynamic (Arr<T[],N>)
    // --- a STORAGE inner dynamic array whose length slot is reached via an AccessPath:
    //     an element of a nested dynamic array (this.dd[i] of u256[][]/string[][]/D[][]),
    //     or a dynamic-array field of a storage struct (this.s.xs). The length lives at
    //     lowerPlace(path).slot; data at keccak(that slot). ---
    | { kind: 'placeArray'; path: AccessPath } // inner dynamic array at a runtime length slot
    | { kind: 'cdDynArrayField'; place: CdDynPlace } // a dynamic value-array field of a calldata dynamic-struct param (s.xs): data via the tuple tail offset
    // an INNER array reached by indexing a NESTED-dynamic-array field of a calldata
    // dynamic-struct param (s.grid[i] of u256[][], s.deep[i][j] of u256[][][]): the
    // field's tail decodes to (tableStart, len) via the navigator, then each index
    // descends one inner-offset-table level. `indices` lists the steps outer-to-inner
    // (>=1); the resolved array's element type is `elem`. Mirrors cdNestedElem but the
    // root array comes from a CdDynPlace field rather than a named param.
    | { kind: 'cdDynFieldNested'; place: CdDynPlace; indices: Expr[] }
    | { kind: 'cdDynFixedField'; place: CdDynPlace; length: number } // an inline fixed-array-of-value field of a calldata dynamic-struct param (s.xs where xs: Arr<T,N>): N element words inline at the field's head offset
    | { kind: 'memArray'; varName: string } // a MEMORY array local (register holds a pointer to [len][elems])
    | { kind: 'memArrayExpr'; expr: Expr }; // a MEMORY array produced by an expression (a ternary etc.); expr lowers to the pointer
  elem: JethType;
  // For a NESTED memory value-array whose OUTER level is FIXED (Arr<u256[],N>, Arr<Arr<u256,2>,2>):
  // the image has NO length header, and element access bounds against this constant N (not mload).
  // Undefined for a dynamic outer (memArray local / dynamic-inner result), which carries a [len] word.
  memFixedLen?: number;
  // For a nested memory value-array element access, whether the element is itself STATIC (an inline
  // sub-image, addressed by base+offset) vs DYNAMIC (the word holds an absolute pointer). Set together
  // with memFixedLen / on a memArray nested access so the codec picks inline-base vs pointer-load.
  memStaticElem?: boolean;
}

// Where an assignment target lives.
export type LValue =
  | { kind: 'state'; type: JethType; slot: bigint; offset: number; varName: string }
  | { kind: 'byteIndexStore'; type: JethType; loc: LValue; index: Expr } // this.b[i] = <bytes1> (loc is the storage `bytes`: direct var / struct field / mapping value / array elem): write byte i (RMW, bounds-checked)
  | { kind: 'immutableStaged'; type: JethType; name: string } // Phase 5: this.<imm> = v inside the constructor (writes the staged shadow; baked via setimmutable)
  | { kind: 'local'; type: JethType; varName: string }
  | {
      kind: 'mapping'; // this.m[k]...[k] write target
      type: JethType; // final value type
      baseSlot: bigint;
      keys: Expr[];
      keyTypes: JethType[];
      varName: string;
    }
  | { kind: 'dynState'; type: JethType; slot: bigint; varName: string } // this.s = <bytes/string>
  | { kind: 'mapDynState'; type: JethType; baseSlot: bigint; keys: Expr[]; keyTypes: JethType[] } // this.m[k] = <bytes/string> (dynamic value at the mapping slot)
  | { kind: 'arrayElem'; type: JethType; arr: ArrayExpr; index: Expr } // a[i] = v (bounds-checked)
  | { kind: 'strArrayElem'; type: JethType; arr: ArrayExpr; index: Expr } // this.ss[i] = <bytes/string>
  | { kind: 'dynPlace'; type: JethType; path: AccessPath } // this.d.s = <bytes/string> (dyn-struct field)
  | { kind: 'place'; type: JethType; path: AccessPath } // nested storage place = v
  | { kind: 'memField'; type: JethType; local: string; wordOffset: number } // p.x = v on a memory-aggregate local
  | { kind: 'memElem'; type: JethType; local: string; index: Expr; length: number; wordOffset?: number } // a[i] = v on a fixed-array memory local (wordOffset: a fixed-array field of a memory struct, p.a[i])
  | { kind: 'memDynField'; type: JethType; local: string; wordOffset: number }; // d.s = <bytes/string> on a dynamic-field struct memory local (re-point the head word to a fresh blob)

// A success condition for an external .call/.staticcall. `cond` is a boolean expression in which the
// scoped bindings `this.ok` (the CALL success bool) and `this.data` (the returndata bytes) are visible;
// if it is false, the call reverts with `reason`. Checks run in declared order; the first failure wins.
export interface SuccessCheck {
  cond: Expr;
  reason: RevertReason;
}

// The right-hand side of a tuple destructuring: a multi-value internal call, or a tuple of expressions.
export type DestructureSource =
  | { kind: 'call'; fn: string; args: Expr[] } // `[a, b] = this.f()` (f has N value return components)
  | { kind: 'tuple'; values: Expr[] } // `[a, b] = [x, y]` (parallel assign / swap)
  // `let [ok, ret] = addr.tryCall/tryStaticcall({...})`: the raw escape hatch (no success checks).
  // Yields two components: ok (bool) and ret (bytes returndata, always captured even on failure).
  | {
      kind: 'extCall';
      op: 'call' | 'staticcall';
      addr: Expr;
      data: Expr;
      value?: Expr;
      gas?: Expr;
      bubble?: boolean;
      codeGuard?: boolean;
    }
  // `let [a, b] = abi.decode(data, [T1, T2])` (and the `.decode([...])` sugar): decode the memory bytes
  // value `data` into N tuple components of `types`. Each component is materialized like the single form
  // (value -> a word, bytes/string/array/struct -> a memory image pointer).
  | { kind: 'abiDecode'; data: Expr; types: JethType[] }
  // `let [ok, signer] = tryRecover(hash, sig)` -> [bool, address]: the never-reverting OZ ECDSA.tryRecover.
  // (false, address(0)) on length!=65 / s>HALF / bad v / zero recovered signer; (true, signer) otherwise.
  | { kind: 'tryRecover'; hash: Expr; sig: Expr }
  // `let [fe, modulus] = pointEvaluation(versionedHash, z, y, commitment, proof)` -> [u256, u256]: the
  // KZG point-evaluation precompile (0x0a, EIP-4844). Emits a length==48 guard on commitment/proof, reverts
  // EMPTY on any failure, yields the two constant success words [FIELD_ELEMENTS_PER_BLOB, BLS_MODULUS].
  | { kind: 'pointEvaluation'; versionedHash: Expr; z: Expr; y: Expr; commitment: Expr; proof: Expr };

export type Stmt =
  | { kind: 'return'; value?: Expr }
  // Phase 5 (full modifiers): the `_;` placeholder marker inside a function's `modifierWrap`. It
  // lowers (in the dispatch case only) to a call of the synthesized body function userfn_<key> with
  // the decoded params, capturing the result into the dispatch's `ret` register(s). Never appears in
  // a normal body or a constructor.
  | { kind: 'modifierBody' }
  | { kind: 'returnTuple'; values: Expr[]; types: JethType[] } // return [a, b, ...] (multi-value)
  | { kind: 'localDecl'; name: string; type: JethType; init?: Expr }
  | { kind: 'assign'; target: LValue; value: Expr } // plain `=` (value already folds compound ops)
  | { kind: 'exprStmt'; expr: Expr }
  | { kind: 'callStmt'; fn: string; args: Expr[] } // internal call as a statement (void or discarded value)
  | { kind: 'deleteStmt'; target: LValue } // `delete x`: reset a storage bytes/string/struct/array (whole mapping = no-op) to its zero value
  | { kind: 'tupleDecl'; names: (string | null)[]; types: JethType[]; source: DestructureSource } // `let [a, , c] = src` (new locals; null = skipped)
  | { kind: 'tupleAssign'; targets: (LValue | null)[]; source: DestructureSource } // `[a, , c] = src` (existing lvalues; null = skipped)
  // --- Phase 2: control flow (each branch/body is its own lexical scope) ---
  | { kind: 'block'; body: Stmt[] }
  | { kind: 'if'; cond: Expr; then: Stmt[]; else?: Stmt[] }
  | { kind: 'while'; cond: Expr; body: Stmt[] }
  | { kind: 'doWhile'; cond: Expr; body: Stmt[] }
  | { kind: 'for'; init?: Stmt; cond?: Expr; post?: Stmt; body: Stmt[] }
  | { kind: 'break' }
  | { kind: 'continue' }
  // --- Phase 2: reverts / custom errors ---
  | { kind: 'require'; cond: Expr; reason: RevertReason }
  | { kind: 'revert'; reason: RevertReason }
  // --- Phase 2: events ---
  | { kind: 'emit'; event: EventIR; args: Expr[] }
  // --- Phase 4: array mutators (statements; both return void) ---
  | { kind: 'push'; arr: ArrayExpr; value?: Expr }
  | { kind: 'pop'; arr: ArrayExpr }
  | { kind: 'bytesPush'; loc: LValue; value?: Expr } // this.b.push(<bytes1>) / push() on a storage `bytes` (loc: direct var / struct field / mapping value / array elem)
  | { kind: 'bytesPop'; loc: LValue } // this.b.pop() on a storage `bytes` (loc: direct var / struct field / mapping value / array elem)
  // --- Phase 6: revertWith(b) bubbles raw bytes as the revert: revert(add(b,0x20), mload(b)) ---
  | { kind: 'revertWith'; value: Expr }
  // --- Phase 6 / Feature 2: try/catch around a high-level interface call ---
  // The controlling call is `call` (a high-level interface call, WITHOUT auto-bubble: failure -> catch).
  // On ok: codeGuard (extcodesize 0 -> OUTER revert empty), decode the returndata into the bound vars
  // (retNames/retTypes; short returndata -> OUTER revert empty), run tryBody. On failure: bind `e` (the
  // verbatim returndata bytes) + (if used) this.reason / this.panic, run catchBody.
  | {
      kind: 'tryCatch';
      call: Expr & { kind: 'extCall' }; // op/addr/data/value/gas; bubble & codeGuard MUST be false (emitted manually)
      retTypes: JethType[]; // [] for a void controlling call; [T] single; [T0,T1,...] tuple
      retNames: (string | null)[]; // bound success-var names (parallel to retTypes; null = skipped)
      tryBody: Stmt[];
      catchName: string | null; // the catch binding `e: bytes` (null = `catch {}` or omitted/unused name)
      usesReason: boolean; // catch body references this.reason
      usesPanic: boolean; // catch body references this.panic
      catchBody: Stmt[];
    };

// A revert payload. 'empty' -> revert(0,0); 'errorString' -> Error(string) blob;
// 'custom' -> a user-declared custom error (selector + ABI-encoded static args).
export type RevertReason =
  | { kind: 'empty' }
  | { kind: 'panic'; code: number } // Panic(uint256) blob: selector 0x4e487b71 + code (assert -> 0x01)
  | { kind: 'errorString'; message: Uint8Array } // precomputed UTF-8 bytes (constant)
  | { kind: 'errorStringDyn'; value: Expr } // Error(string) from a runtime bytes/string value
  | { kind: 'custom'; decl: ErrorDecl; args: Expr[] };

// A declared custom error. selector = keccak256(canonicalSig)[0:4] hex, no 0x.
export interface ErrorDecl {
  name: string;
  params: Param[];
  signature: string; // canonical, e.g. "Insufficient(uint256,uint256)"
  selector: string; // 4-byte hex, no 0x
}

// Phase 6: a method of an @interface declaration. Bodyless; carries its precomputed canonical
// selector and ABI shape. `returnTypes` is set for a multi-value (tuple) return; for a single-value
// return `returnTypes` is undefined and `returnType` holds the type (void = no return).
export interface InterfaceMethod {
  name: string;
  params: Param[];
  returnType: JethType; // VOID when the method returns nothing or has a tuple return
  returnTypes?: JethType[]; // a >=2-component tuple return (returnType is VOID then)
  mutability: Mutability; // view/pure -> STATICCALL; nonpayable/payable -> CALL ({value} only if payable)
  signature: string; // canonical, e.g. "bar(uint256)"
  selector: string; // 4-byte hex, no 0x
}

// Phase 6: an @interface declaration. Emits NO bytecode; it is purely a named type + the per-method
// {selector, mutability, params, return} registry used to lower a high-level typed call IFoo(addr).m(..).
export interface InterfaceDecl {
  name: string;
  methods: Map<string, InterfaceMethod>; // method name -> shape (no overloading in v1)
}

export interface EventParam {
  name: string;
  type: JethType;
  indexed: boolean;
}

export interface EventIR {
  name: string;
  params: EventParam[]; // source declaration order
  signature: string; // canonical, NO 'indexed'
  topic0: string; // 64-hex (no 0x): keccak256(signature)
  anonymous: boolean; // @anonymous events omit topic0 (LOG carries only the indexed params)
}

export interface StateVar {
  name: string;
  type: JethType;
  slot: bigint;
  offset: number; // byte offset within the slot for packing
  // constant-folded initializer value, if any and non-zero (emitted in constructor)
  initialValue?: bigint | boolean;
}

export interface Param {
  name: string;
  type: JethType;
}

export interface FunctionIR {
  name: string;
  key: string; // unique identity (the bare name when unique, else `name__ovN` for an overload, or a
  // generic mangled name): the internal-call target id (Yul `userfn_<key>`), distinct from `name`
  // (which is the source name shared by overloads, used for diagnostics + the ABI signature)
  visibility: Visibility;
  mutability: Mutability;
  params: Param[];
  returnType: JethType; // VOID if none (or if returnTypes is set for a multi-value return)
  returnTypes?: JethType[]; // a multi-value return `[T1, T2, ...]` (ABI: N outputs)
  signature: string; // canonical, e.g. "increment()"
  selector: string; // 4-byte hex without 0x, e.g. "d09de08a"
  body: Stmt[];
  internallyCalled?: boolean; // a target of at least one internal call -> emit a Yul function def
  nonReentrant?: boolean; // F4: wrap the external entry in a transient-storage (TSTORE/TLOAD) mutex
  // Phase 5 (full modifiers): set when at least one applied @modifier has POST-placeholder code. The
  // function `body` stays the RAW wrapped body Z (emitted as userfn_<key>, forced internallyCalled);
  // the dispatch case lowers THIS nested pre/post structure instead of the body, where a single
  // `{kind:'modifierBody'}` marker calls userfn_<key>(<decoded params>) and captures its result, then
  // the dispatch ABI-encodes that result ONCE (so a `return` in Z runs the enclosing post-code first).
  modifierWrap?: Stmt[];
  // Phase 5 (full modifiers, JETH323): one argument Expr per wrapped-function param that the
  // {modifierBody} marker passes to userfn_<key>(...). A value param echoes as a register; an
  // aggregate/dynamic param echoes as a memory pointer (the dispatch's lowerCallArgs materializes it).
  // Set iff modifierWrap is set. Lets the userfn take aggregate/dynamic params byte-identical to solc.
  modifierArgs?: Expr[];
  // Inheritance: the contract (in the C3 linearization) that DEFINED this function body. The
  // override WINNER (most-derived definition of a signature) keeps the bare ABI key + selector and
  // is dispatched; non-winning base versions are retained ONLY as `super` targets and carry a
  // per-contract key (e.g. `Base__f`). Unset for a non-inherited (single-contract) compile.
  definingContract?: string;
  // Phase 2c (UUPS): a SYNTHESIZED upgrade entry of a `@uups @contract`. The body is NOT lowered from
  // `body` (which is empty); yul.ts emits a dedicated hand-written body (byte-identical to OZ
  // UUPSUpgradeable 5.x). 'upgradeToAndCall' = the upgrade entry (calls authorizeKey, the anti-brick
  // proxiableUUID staticcall, then the EIP-1967 upgrade); 'proxiableUUID' = returns the EIP-1967 impl slot.
  uupsKind?: 'upgradeToAndCall' | 'proxiableUUID';
  // Phase 2c (UUPS): for a uupsKind==='upgradeToAndCall' entry, the Yul userfn_<key> of the user-declared
  // `authorizeUpgrade(address)` gate, called with the decoded newImpl before the upgrade runs.
  authorizeKey?: string;
  // Phase 2d (BEACON): a SYNTHESIZED entry of a `@beacon class` (the OZ UpgradeableBeacon 5.x surface).
  // The body is NOT lowered from `body` (empty); yul.ts emits a dedicated hand-written body.
  //  - 'upgradeTo'      : upgradeTo(address newImpl) - owner-gated; isContract(newImpl); store impl slot;
  //                       emit Upgraded(indexed newImpl). (owner held in fixed storage slot 0.)
  //  - 'implementation' : implementation() view returns address - SLOAD the impl slot (fixed slot 1).
  //  - 'owner'          : owner() view returns address - SLOAD slot 0 (the OZ Ownable._owner layout).
  beaconKind?: 'upgradeTo' | 'implementation' | 'owner';
}

/** A constructor (Phase 5): runs once in creation code. Not callable, not in the dispatcher;
 *  params are ABI-decoded from the args appended to the init code (decoded from MEMORY, not
 *  calldata). `payable` controls the non-payable callvalue guard. */
export interface ConstructorIR {
  params: Param[];
  payable: boolean;
  body: Stmt[];
}

/** Phase 5: an @immutable field. Assigned once in the constructor, baked into runtime code via
 *  setimmutable, read via loadimmutable. Consumes NO storage slot (never a StateVar). */
export interface ImmutableVar {
  name: string;
  type: JethType;
}

/** Phase 6: a @receive / @fallback special runtime entry. Lowered INLINE in the dispatcher prologue
 *  (emitRuntime), not a selectable function. @receive is always payable; @fallback is non-payable by
 *  default (the `if callvalue(){revert}` guard) unless `payable`. `returnsBytes` stays false in v1
 *  (the raw-bytes-returning fallback is gated). The body is ordinary Stmt[] (a constructor-like body). */
export interface SpecialEntryIR {
  payable: boolean;
  returnsBytes: boolean;
  body: Stmt[];
}

export interface ContractIR {
  name: string;
  stateVars: StateVar[];
  functions: FunctionIR[];
  errors: ErrorDecl[];
  events: EventIR[];
  // number of 32-byte slots consumed by state (for diagnostics / layout dump)
  slotCount: number;
  ctor?: ConstructorIR; // a constructor, if declared (Phase 5)
  immutables: ImmutableVar[]; // @immutable fields (declaration order), baked via setimmutable
  receive?: SpecialEntryIR; // @receive: empty-calldata ETH receiver (Phase 6)
  fallback?: SpecialEntryIR; // @fallback: catch-all entry (Phase 6)
  // Phase 2a: `@proxy class P` -> JETH synthesizes the canonical EIP-1967 delegate fallback (forward ALL
  // calldata to the EIP-1967 impl slot) in the runtime fallback position. The proxy has no @state of its
  // own (storage belongs to the impl) and may NOT declare a user @receive/@fallback.
  isProxy?: boolean;
  // Phase 2b/2d: the proxy variant. undefined = the plain Phase-2a delegate-only proxy. 'transparent' =
  // `@proxy('transparent')`, an OZ TransparentUpgradeableProxy-equivalent: the synthesized fallback routes
  // by caller() - the admin may ONLY call upgradeToAndCall(address,bytes) (else revert ProxyDeniedAdminAccess),
  // a non-admin ALWAYS delegates to the impl (even an upgradeToAndCall selector - this defeats the clash).
  // 'beacon' = `@proxy('beacon')`, an OZ BeaconProxy-equivalent: the fallback reads the EIP-1967 BEACON slot,
  // STATICCALLs beacon.implementation() (0x5c60da1b) for the CURRENT impl on EVERY call (revert if it fails),
  // then the standard delegate tail. The proxy stores no impl slot of its own (it lives behind the beacon).
  proxyVariant?: 'transparent' | 'beacon';
  // Phase 2d: `@beacon class B` - the UpgradeableBeacon contract (byte-identical to OZ UpgradeableBeacon 5.x).
  // JETH synthesizes the whole boilerplate: a constructor (owner = msg.sender at slot 0; impl arg
  // isContract-checked + stored at slot 1; emit Upgraded(indexed impl)) and three @external entries -
  // upgradeTo(address) (owner-gated upgrade + Upgraded event), implementation() and owner() (view getters).
  // The user writes only `@beacon class B { constructor(impl: address) {} }`.
  isBeacon?: boolean;
  // Phase 2c: `@uups @contract` - the IMPLEMENTATION opts into the UUPS upgrade surface (the proxy used
  // with it is the plain Phase-2a `@proxy`). JETH synthesizes two @external dispatcher entries:
  // upgradeToAndCall(address,bytes) (user authorizeUpgrade gate -> anti-brick proxiableUUID staticcall ->
  // the EIP-1967 upgrade) and proxiableUUID() (returns the EIP-1967 impl slot). Byte-identical to OZ
  // UUPSUpgradeable 5.x. The two entries are ordinary FunctionIRs carrying a uupsKind flag.
  isUups?: boolean;
  // Phase 3 (DIAMOND): `@diamond('array')` - an EIP-2535 diamond. JETH synthesizes the whole surface
  // (the diamond-3 namespaced storage struct, diamondCut + the 4 loupe fns + ERC-165 + ownership, the
  // DiamondCut/OwnershipTransferred events) as ordinary contract members, then emitRuntime adds the
  // selector-routed delegatecall fallback (the router) after the diamond's own selector switch. The
  // facets() loupe is emitted as a raw-Yul dispatch case (it builds a Facet[] from the split storage).
  isDiamond?: boolean;
  diamondVariant?: 'array' | 'packed' | 'solidstate'; // the storage layout model: 'array' (diamond-1/3
  // array-storing), 'packed' (diamond-2: mapping(bytes4=>bytes32) facets + 8-selectors-per-slot selectorSlots
  // + uint16 count), or 'solidstate' (the packed diamond-2 selector storage at solidstate's own bases + a
  // settable default fallback address + SafeOwnable 2-step ownership in separate namespaces).
  // The raw diamond-storage struct base = keccak256("diamond.standard.diamond.storage") and the field
  // SLOT (base + relative slot) of selectorToFacetAndPosition, used by the router's facet lookup.
  diamondStorageBase?: bigint;
  diamondSel2FacetSlot?: bigint;
  // Phase B: external (delegatecall) libraries this contract references. Each is emitted as its OWN
  // top-level Yul object (creation returns runtime; runtime = a selector dispatcher over its external
  // functions) and linked at deploy time. Empty/absent when no external library is referenced.
  libraries?: LibraryIR[];
}

/** Phase B: an external (delegatecall) library compiled to its OWN deployable Yul object. `external`
 *  are its @external functions (the delegatecall entry points, dispatched by selector); `internal` are
 *  the library's own functions reachable from an external one (emitted as object-local userfn_s). No
 *  state, constructor, immutables, or special entries (a library has none). */
export interface LibraryIR {
  name: string;
  external: FunctionIR[];
  internal: FunctionIR[];
}
