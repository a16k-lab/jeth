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
  | { kind: 'stateRead'; type: JethType; slot: number; offset: number; varName: string }
  // Phase 5 immutables: a runtime read lowers to loadimmutable("name") (baked into code, no slot);
  // a read INSIDE the constructor body reads the staged shadow (the value assigned so far).
  | { kind: 'immutableRead'; type: JethType; name: string }
  | { kind: 'immutableStagedRead'; type: JethType; name: string }
  | { kind: 'localRead'; type: JethType; name: string }
  | { kind: 'binary'; type: JethType; op: BinOp; left: Expr; right: Expr; unchecked: boolean }
  | { kind: 'ternary'; type: JethType; cond: Expr; then: Expr; else: Expr } // c ? a : b (short-circuit)
  | { kind: 'incDec'; type: JethType; target: LValue; readExpr: Expr; isInc: boolean; prefix: boolean; unchecked: boolean } // x++ / ++x in value position
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
      baseSlot: number;
      keys: Expr[]; // outer-to-inner
      keyTypes: JethType[];
    }
  // --- Phase 4: dynamic bytes/string values (references, not 256-bit words) ---
  | { kind: 'dynStateRead'; type: JethType; slot: number } // this.s (storage)
  | { kind: 'dynParamRead'; type: JethType; name: string } // calldata param (codegen binds ptr/len)
  | { kind: 'msgData'; type: JethType } // msg.data: a calldata bytes view over the WHOLE calldata [0, calldatasize())
  | { kind: 'dynLocalRead'; type: JethType; name: string } // bytes/string MEMORY local (register holds a [len][data] pointer)
  | { kind: 'stringLiteral'; type: JethType; bytes: Uint8Array } // a memory bytes/string literal
  | { kind: 'dynLength'; type: JethType; operand: Expr } // s.length -> u256
  | { kind: 'keccak'; type: JethType; arg: Expr } // keccak256(bytes/string) -> bytes32
  | { kind: 'precompileHash'; type: JethType; arg: Expr; addr: number; leftShift: number } // sha256(0x02)->bytes32 / ripemd160(0x03)->bytes20
  | { kind: 'modOp'; type: JethType; op: 'addmod' | 'mulmod'; a: Expr; b: Expr; m: Expr } // addmod/mulmod -> u256
  | { kind: 'abiEncode'; type: JethType; packed: boolean; args: Expr[]; selector?: Expr; sig?: Expr } // abi.encode/encodePacked/encodeWithSelector(selector)/encodeWithSignature(sig) -> bytes
  | { kind: 'blockhash'; type: JethType; arg: Expr } // blockhash(uint) -> bytes32
  | { kind: 'blobhash'; type: JethType; arg: Expr } // blobhash(uint) -> bytes32 (EIP-4844)
  | { kind: 'balance'; type: JethType; addr: Expr } // <address>.balance -> u256
  | { kind: 'byteIndex'; type: JethType; base: Expr; index: Expr } // b[i] -> bytes1
  // --- Phase 4: dynamic arrays T[] ---
  | { kind: 'arrayLen'; type: JethType; arr: ArrayExpr } // a.length -> u256
  | { kind: 'arrayGet'; type: JethType; arr: ArrayExpr; index: Expr; oobEmpty?: boolean } // a[i] read (bounds-checked; oobEmpty: revert(0,0) instead of Panic 0x32, for @public getters)
  | { kind: 'arrayValue'; type: JethType; arr: ArrayExpr } // a whole array (for return encoding)
  | { kind: 'arrayLit'; type: JethType; elem: JethType; elements: Expr[] } // [a,b,c] -> memory T[]
  | { kind: 'newArray'; type: JethType; elem: JethType; length: Expr } // new T[](n) -> zeroed memory T[]
  // --- Phase 4c: structs ---
  | { kind: 'structNew'; type: JethType; fields: StructField[]; args: Expr[] } // Point(a, b)
  | { kind: 'structValue'; type: JethType; baseSlot: number } // whole storage struct (for return)
  | { kind: 'memField'; type: JethType; local: string; wordOffset: number } // read a value field/element of a memory-aggregate local (p.x)
  | { kind: 'memElem'; type: JethType; local: string; index: Expr; length: number; wordOffset?: number } // a[i] on a fixed-array memory local (value element, bounds-checked); wordOffset: a fixed-array FIELD of a memory struct (p.a[i]) starts that many words into the image
  | { kind: 'memAggregate'; type: JethType; local: string; wordOffset?: number } // a whole memory aggregate, or a nested struct field at wordOffset (sub-pointer into the parent image)
  | { kind: 'memDynStructValue'; type: JethType; local: string } // a whole DYNAMIC-field struct memory local (head: value fields inline, bytes/string fields as pointers)
  | { kind: 'memDynField'; type: JethType; local: string; wordOffset: number } // a bytes/string field of a memory dynamic struct (the head word holds the [len][data] pointer)
  | { kind: 'structArrayElem'; type: JethType; arr: ArrayExpr; index: Expr } // whole storage/fixed/mapping struct element this.recs[i] (for return / copy source)
  | { kind: 'mapStorageValue'; type: JethType; baseSlot: number; keys: Expr[]; keyTypes: JethType[] } // return this.m[k] (whole struct/array mapping value)
  | { kind: 'mapDynValue'; type: JethType; baseSlot: number; keys: Expr[]; keyTypes: JethType[] } // this.m[k] where the value is bytes/string (dynamic value at the mapping slot)
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
  | { kind: 'cdArrayField'; type: JethType; arr: ArrayExpr; index: Expr; headWords: number; fieldType: JethType; elemIndex?: Expr; elemLength?: number }
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
  | { kind: 'cdDynStructValue'; type: JethType; param: string };

/** A storage location reached by navigating a chain of field/index/key steps from
 *  a root state variable. Resolves at codegen to a (slot expr, byte offset). */
export interface AccessPath {
  baseSlot: number;
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
    | { kind: 'stateArray'; slot: number } // dynamic T[] state var (length at slot)
    | { kind: 'calldataArray'; name: string } // dynamic T[] calldata param
    | { kind: 'fixedArray'; baseSlot: number; length: number } // fixed Arr<T,N> (inline at baseSlot)
    | { kind: 'mapArray'; baseSlot: number; keys: Expr[]; keyTypes: JethType[] } // dynamic T[] mapping value (length at keccak(key.baseSlot))
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
    | { kind: 'cdDynFixedField'; place: CdDynPlace; length: number } // an inline fixed-array-of-value field of a calldata dynamic-struct param (s.xs where xs: Arr<T,N>): N element words inline at the field's head offset
    | { kind: 'memArray'; varName: string } // a MEMORY array local (register holds a pointer to [len][elems])
    | { kind: 'memArrayExpr'; expr: Expr }; // a MEMORY array produced by an expression (a ternary etc.); expr lowers to the pointer
  elem: JethType;
}

// Where an assignment target lives.
export type LValue =
  | { kind: 'state'; type: JethType; slot: number; offset: number; varName: string }
  | { kind: 'byteIndexStore'; type: JethType; loc: LValue; index: Expr } // this.b[i] = <bytes1> (loc is the storage `bytes`: direct var / struct field / mapping value / array elem): write byte i (RMW, bounds-checked)
  | { kind: 'immutableStaged'; type: JethType; name: string } // Phase 5: this.<imm> = v inside the constructor (writes the staged shadow; baked via setimmutable)
  | { kind: 'local'; type: JethType; varName: string }
  | {
      kind: 'mapping'; // this.m[k]...[k] write target
      type: JethType; // final value type
      baseSlot: number;
      keys: Expr[];
      keyTypes: JethType[];
      varName: string;
    }
  | { kind: 'dynState'; type: JethType; slot: number; varName: string } // this.s = <bytes/string>
  | { kind: 'mapDynState'; type: JethType; baseSlot: number; keys: Expr[]; keyTypes: JethType[] } // this.m[k] = <bytes/string> (dynamic value at the mapping slot)
  | { kind: 'arrayElem'; type: JethType; arr: ArrayExpr; index: Expr } // a[i] = v (bounds-checked)
  | { kind: 'strArrayElem'; type: JethType; arr: ArrayExpr; index: Expr } // this.ss[i] = <bytes/string>
  | { kind: 'dynPlace'; type: JethType; path: AccessPath } // this.d.s = <bytes/string> (dyn-struct field)

  | { kind: 'place'; type: JethType; path: AccessPath } // nested storage place = v
  | { kind: 'memField'; type: JethType; local: string; wordOffset: number } // p.x = v on a memory-aggregate local
  | { kind: 'memElem'; type: JethType; local: string; index: Expr; length: number; wordOffset?: number } // a[i] = v on a fixed-array memory local (wordOffset: a fixed-array field of a memory struct, p.a[i])
  | { kind: 'memDynField'; type: JethType; local: string; wordOffset: number }; // d.s = <bytes/string> on a dynamic-field struct memory local (re-point the head word to a fresh blob)

// The right-hand side of a tuple destructuring: a multi-value internal call, or a tuple of expressions.
export type DestructureSource =
  | { kind: 'call'; fn: string; args: Expr[] } // `[a, b] = this.f()` (f has N value return components)
  | { kind: 'tuple'; values: Expr[] }; // `[a, b] = [x, y]` (parallel assign / swap)

export type Stmt =
  | { kind: 'return'; value?: Expr }
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
  | { kind: 'bytesPop'; loc: LValue }; // this.b.pop() on a storage `bytes` (loc: direct var / struct field / mapping value / array elem)

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
  slot: number;
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
}
