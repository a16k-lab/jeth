// Semantic analysis + type checking. Produces a typed ContractIR from the TS AST.
//
// Responsibilities (directive §5 steps 3-5):
//  - find the @contract class, classify members;
//  - resolve decorators into visibility/mutability metadata;
//  - plan storage layout;
//  - type-check each function body into typed IR (checked-by-default arithmetic),
//    enforcing integer widths, BigInt-literal rule, and view/pure mutability.
import ts from 'typescript';
import type { DiagnosticBag } from './diagnostics.js';
import { decoratorNames, ctorDecoratorNames, decoratorCall, heritageBases, HeritageBase } from './parser.js';
import { resolveType, resolvePrimitiveName } from './typeresolver.js';
import {
  JethType,
  VOID,
  U256,
  I256,
  BOOL,
  displayName,
  canonicalName,
  typesEqual,
  isInteger,
  isEnum,
  isImplicitWiden,
  commonNumericType,
  isStaticValueType,
  isStaticType,
  isDynamicType,
  isBytesLike,
  storageByteSize,
  storageSlotCount,
  abiHeadWords,
  intRange,
  StructField,
} from './types.js';
import {
  ContractIR,
  ConstructorIR,
  SpecialEntryIR,
  FunctionIR,
  StateVar,
  Stmt,
  Expr,
  LValue,
  ArrayExpr,
  AccessPath,
  AccessStep,
  CalldataPlace,
  CdStep,
  CdDynPlace,
  CdDynStep,
  BinOp,
  GlobalOp,
  Visibility,
  Mutability,
  Param,
  ErrorDecl,
  EventIR,
  EventParam,
  RevertReason,
  SuccessCheck,
  DestructureSource,
  InterfaceDecl,
  InterfaceMethod,
  LibraryIR,
} from './ir.js';

const ADDRESS: JethType = { kind: 'address', payable: false };
const STRING: JethType = { kind: 'string' };
const BYTES1: JethType = { kind: 'bytesN', size: 1 };
const BYTES: JethType = { kind: 'bytes' };
// Phase 6 external low-level call methods. call/staticcall return bytes (with mandatory success
// checks); tryCall/tryStaticcall return [bool, bytes] (raw escape hatch, only in a tuple destructure).
const EXT_CALL_METHODS = new Set(['call', 'staticcall', 'tryCall', 'tryStaticcall']);

// Environment globals: "<obj>.<field>" -> opcode + type + category.
// 'env' forbidden in @pure; 'value' (msg.value) requires @payable; 'calldata'
// (msg.sig) allowed in @pure. Verified opcode/type/mutability against solc 0.8.
type GlobalCat = 'env' | 'value' | 'calldata';
const GLOBALS: Record<string, Record<string, { op: GlobalOp; type: JethType; cat: GlobalCat }>> = {
  msg: {
    sender: { op: 'caller', type: ADDRESS, cat: 'env' },
    value: { op: 'callvalue', type: U256, cat: 'value' },
    sig: { op: 'msgsig', type: { kind: 'bytesN', size: 4 }, cat: 'calldata' },
  },
  tx: {
    origin: { op: 'origin', type: ADDRESS, cat: 'env' },
    gasprice: { op: 'gasprice', type: U256, cat: 'env' },
  },
  block: {
    timestamp: { op: 'timestamp', type: U256, cat: 'env' },
    number: { op: 'number', type: U256, cat: 'env' },
    chainid: { op: 'chainid', type: U256, cat: 'env' },
    coinbase: { op: 'coinbase', type: ADDRESS, cat: 'env' },
    basefee: { op: 'basefee', type: U256, cat: 'env' },
    gaslimit: { op: 'gaslimit', type: U256, cat: 'env' },
    prevrandao: { op: 'prevrandao', type: U256, cat: 'env' },
    // post-Merge `block.difficulty` is the same DIFFICULTY/PREVRANDAO opcode (0x44); solc maps both here.
    difficulty: { op: 'prevrandao', type: U256, cat: 'env' },
    // EIP-4844 (cancun): block.blobbasefee -> BLOBBASEFEE opcode (0x4a); env read (view, not pure).
    blobbasefee: { op: 'blobbasefee', type: U256, cat: 'env' },
  },
};
import { planLayout, RawStateVar } from './layout.js';
import { functionSignature, functionSelector, eventTopic0, keccak, toHex } from './selectors.js';

/** Unwrap redundant parentheses: `(xs)` / `((this.a))` -> the inner expression. */
function stripParens(node: ts.Expression): ts.Expression {
  while (ts.isParenthesizedExpression(node)) node = node.expression;
  return node;
}

interface RawFunction {
  node: ts.MethodDeclaration;
  name: string;
  visibility: Visibility; // provisional when an infer flag is set; resolved after the fixpoint
  mutability: Mutability; // provisional ('view') when inferRead is set; resolved after the fixpoint
  params: { name: string; type: JethType }[];
  defaults?: (ts.Expression | undefined)[]; // F3: per-param constant default (call-site fill), aligned with params
  returnType: JethType;
  returnTypes?: JethType[]; // multi-value return `[T1, T2, ...]`
  inferRead?: boolean; // @read -> resolve to @pure (touches no state/env) or @view (reads, never writes)
  nonReentrant?: boolean; // F4: @nonReentrant -> transient-storage reentrancy mutex on the external entry
  modifiers?: { name: string; argNodes: ts.Expression[]; site: ts.Node }[]; // Phase 5: applied @modifier decorators, in source order (leftmost = outermost)
  key?: string; // unique identity for the call graph: the bare name when unique, `name__ovN` when
  // overloaded (a generic specialization sets name=key=mangled). Unset => `name` (see fkey()).
  // ---- inheritance metadata (set by collectFunction) ----
  isVirtual?: boolean; // @virtual: this function may be overridden by a more-derived contract
  isOverride?: boolean; // @override (bare or @override(B,C)): redefines a base function
  overrideList?: string[]; // the explicit base list of @override(B, C) (a diamond redefinition)
  bodyless?: boolean; // an unimplemented @virtual (no body): a base abstract method
  definingContract?: string; // the contract (in the linearization) that declared this function
  // Phase B: this function belongs to a @library (libraryName set). libraryExternal -> an @external
  // (delegatecall) library function: NOT inlined into the contract, called via DELEGATECALL to its own
  // deployed library object, and emitted as a selector-dispatched entry in that object's runtime.
  libraryName?: string;
  libraryExternal?: boolean;
}

// Phase 5: a user-defined @modifier (Solidity-style). A `_;` placeholder splits the body into PRE
// code (runs before the wrapped function body) and POST code (runs after). A pre-only modifier (the
// placeholder is the LAST statement) inlines as [pre, body] with no buffered-return machinery; a
// modifier with POST code needs the buffered-return path (see FunctionIR.modifierWrap): the wrapped
// body is lowered as a synthesized Yul function so a `return` in it runs the enclosing post-code
// before the value is ABI-encoded once. EXACTLY ONE placeholder, at TOP LEVEL of the body (never
// inside an if/for/while - that 0-or-N-times shape is gated JETH321).
interface RawModifier {
  name: string;
  node: ts.MethodDeclaration;
  params: { name: string; type: JethType }[];
  preStmts: ts.Statement[]; // the statements before the placeholder (the pre-condition guard)
  postStmts: ts.Statement[]; // the statements after the placeholder (run after the wrapped body)
  // The 0-or-N-times shape: the SINGLE `_;` placeholder is nested inside an if/for/while, so the body
  // cannot be split into flat pre/post slices. Instead the WHOLE body is lowered with the placeholder
  // replaced IN PLACE by the {modifierBody} marker (the body call sits inside the conditional, running
  // 0-or-N times; a 0-times path leaves the buffered `ret` at its zero-init = solc's zero value). Set
  // ONLY for this shape (preStmts/postStmts stay empty); it always routes through the buffered userfn
  // path (like POST code) so a value-returning function's zero-value branch works.
  bodyStmts?: ts.Statement[];
}

export class Analyzer {
  // state symbols, available once layout is planned
  private stateByName = new Map<string, StateVar>();
  private publicStateNames = new Set<string>(); // @public @state vars that get an auto-generated getter
  // @constant fields: slot-free compile-time constants. The folded literal is inlined at every
  // read site (no SLOAD, no storage slot), so a @constant never shifts the slot of a @state var.
  private constantsByName = new Map<string, { value: bigint | boolean | Uint8Array; type: JethType }>();
  // @immutable fields (Phase 5): value-type, assigned once in the constructor, baked into runtime
  // code via setimmutable (NO storage slot - never enters rawState/planLayout). immutableOrder keeps
  // declaration order for deterministic setimmutable emission. currentInConstructor distinguishes a
  // staged ctor-body read (the value assigned so far) from a runtime loadimmutable read.
  private immutablesByName = new Map<string, { name: string; type: JethType; init?: ts.Expression }>();
  private immutableOrder: string[] = [];
  private publicImmutableNames = new Set<string>(); // @external @immutable fields that get an auto-generated view getter
  private currentInConstructor = false;
  // Set ONLY while lowering a CONDITIONAL-placeholder modifier body (the 0-or-N-times shape): when
  // checkStatement encounters the single `_;` placeholder (anywhere, incl. nested in an if/for/while),
  // it splices THESE marker statements in place instead of treating `_` as an expression. The marker
  // is the {modifierBody} call (or the inner modifier's wrap), so the body runs where `_;` sat.
  private placeholderInner: Stmt[] | undefined;
  // @storage('ns') namespaced fields (EIP-7201): each distinct `ns` string forms one logical struct
  // laid out from slot 0 by the SAME planLayout (sequential + packing), then offset by the namespace
  // base (ERC-7201 keccak). Insertion-ordered: ns string -> the fields declared in it (most-base-first,
  // matching the @state collection order). Kept OUT of rawState so @storage never shifts @state slots.
  private namespacedStorage = new Map<string, RawStateVar[]>();
  // Synthesis-only: namespaces whose base slot is the RAW keccak256(ns) (the diamond-standard
  // base, byte-matching mudgen's DIAMOND_STORAGE_POSITION) instead of the ERC-7201 user formula.
  // A `@storage('ns', 'raw')` field (used only by the synthesized @diamond) lands here.
  private rawNamespaces = new Set<string>();
  // Phase 5: user-defined @modifier declarations (name -> RawModifier). A modifier is never a
  // standalone function (not callable, not in the ABI); it is inlined around each function it decorates.
  private modifiersByName = new Map<string, RawModifier>();
  // @struct declarations (name -> resolved struct type), collected before contracts
  private structsByName = new Map<string, JethType>();
  // contract-level custom error and event tables (collected before function bodies)
  private errorsByName = new Map<string, ErrorDecl>();
  private errors: ErrorDecl[] = [];
  private eventsByName = new Map<string, EventIR[]>(); // source name -> all overloads (solc allows event overloading by signature)
  private events: EventIR[] = [];
  // Phase 6: @interface declarations (name -> {methods}); emits no bytecode, names a type + ABI shape.
  private interfacesByName = new Map<string, InterfaceDecl>();
  // Phase A libraries: `@library class L { f(...) {...} }`. Each library's functions are collected as
  // ORDINARY internal functions (no state, no ctor, never @external/@payable) keyed by a qualified
  // source name `L.f`, registered into the SAME candidatesByName/funcsByName/userfn_ machinery as a
  // contract's internal functions - so `L.f(args)` and an attached `x.f(args)` lower to the existing
  // internal-call path and are byte-identical to solc's internal library functions for free. The
  // registry holds each library's RawFunctions (decl order) for overload resolution at the call site.
  private libraryByName = new Map<string, RawFunction[]>();
  // `@using(L)` attachment: when a @contract carries @using(L) decorators, each L function whose FIRST
  // param type is T attaches as a method on T, so `x.f(args)` desugars to `L.f(x, ...args)`. Built per
  // deployed contract from its @using list; keyed by `${canonicalName(T)}#${methodName}` -> the matching
  // RawFunctions (more than one => ambiguous attachment, rejected). A built-in method on T wins (the
  // attachment is consulted only AFTER the built-in method resolvers in the call dispatch).
  private libraryAttachments = new Map<string, RawFunction[]>();
  // Phase B: names of @library declarations that an external (delegatecall) call site referenced (so
  // compile.ts knows which library objects to emit + link). Populated when a `L.f`/attached `x.f`
  // resolves to an @external library function.
  private referencedExternalLibraries = new Set<string>();
  // per-function lexical scope stack (innermost last); each scope maps name -> type.
  private scopes: Map<string, JethType>[] = [];
  private loopDepth = 0; // > 0 inside a for/while body (gates break/continue)
  private currentMutability: Mutability = 'nonpayable';
  private currentWritesState = false;
  private currentReadsState = false;
  private currentUnchecked = false; // inside an unchecked { } block (arithmetic wraps)
  private currentReturnTypes: JethType[] | undefined; // multi-value return components, if any
  private memArrayLocals = new Set<string>(); // let-locals that are MEMORY arrays (vs calldata-array params)
  private memAggregateLocals = new Map<string, JethType>(); // STATIC struct / fixed-array MEMORY locals (G9): name -> type
  private memDynLocals = new Set<string>(); // bytes/string MEMORY locals (G9): register holds a [len][data] pointer
  private memDynStructLocals = new Map<string, JethType>(); // DYNAMIC-field struct MEMORY locals: name -> struct type (head = one word per field, value inline / bytes-string a pointer)
  private currentReadsEnv = false; // reads msg.*/block.*/tx.*/address(this) -> forbidden in @pure
  // Inheritance: the contract whose body is currently being checked (for super.f() resolution). A
  // super.f() inside this contract's function resolves to the FIRST version after it in the override
  // chain. Undefined for a non-inherited single-contract compile (no super possible).
  private currentDefiningContract: string | undefined;
  // Phase 6: scoped bindings visible ONLY inside a .call/.staticcall `success` condition. While checking
  // a condition expression, `this.ok` resolves to the call's success bool and `this.data` to the
  // returndata bytes (consulted in the `this.<X>` resolution BEFORE constant/immutable/state lookup,
  // so they shadow nothing globally and never leak outside the condition).
  private callResultBindings: Map<string, JethType> | undefined;
  // Feature 2: scoped bindings visible ONLY inside a try/catch CATCH body. While checking the catch body,
  // `this.reason` resolves to the decoded Error(string) message (string) and `this.panic` to the decoded
  // Panic code (u256). Resolved in `this.<X>` BEFORE constant/immutable/state lookup, like callResultBindings.
  // A reference outside a catch errors (JETH065). Set/restored around the catch body only; whether each was
  // actually referenced is recorded in catchUsesReason / catchUsesPanic for usage-gated codegen.
  private catchBindings: Map<string, JethType> | undefined;
  private catchUsesReason = false;
  private catchUsesPanic = false;
  // whether the function being checked is EXTERNALLY reachable (external/public, incl. an inferred-
  // exposed no-visibility function). Reading msg.value in such a function requires @payable; an
  // internal/private function may read it at any non-pure mutability (solc parity). Default strict
  // (true) so constructors / field initializers keep requiring @payable.
  private currentExternallyReachable = true;
  // internal-call support (G8): the function registry (built before bodies so calls can
  // forward-reference), plus per-function direct-effect / callee tracking for the
  // transitive-purity fixpoint and the set of names actually called internally.
  private funcsByName = new Map<string, RawFunction>();
  private candidatesByName = new Map<string, RawFunction[]>(); // source name -> all overloads (decl order)
  private currentCallees = new Set<string>(); // internal callee KEYS of the function being checked
  private internallyCalled = new Set<string>(); // KEYS of functions that are the target of an internal call
  // F6: compile-time generics (monomorphization). A generic internal function `f<T>(...)` is NOT a
  // normal function; it is a template. On each internal call we resolve concrete type arguments
  // (explicit `f<u256>(x)` or inferred from the value args), register the type params -> concrete
  // JethTypes in structsByName, and synthesize a mangled non-generic specialization that flows
  // through the EXISTING collect/check/emit internal-function pipeline. Specializations are
  // discovered lazily while checking bodies, so a worklist is drained until no new ones appear.
  private genericsByName = new Map<string, { node: ts.MethodDeclaration; typeParams: string[] }>();
  private specializedNames = new Map<string, string>(); // specialization KEY -> mangled function name
  private specializationQueue: { mangled: string; node: ts.MethodDeclaration; binding: Map<string, JethType> }[] = []; // not-yet-checked specializations

  constructor(
    private readonly sourceFile: ts.SourceFile,
    private readonly diags: DiagnosticBag,
    // Phase 3: set when this compilation unit's deployed contract is a synthesized @diamond (the source
    // was expanded from `@diamond('array')`); marks the ContractIR so emitRuntime adds the router.
    private readonly diamond?: { name: string; variant: 'array' | 'packed' | 'solidstate' },
  ) {}

  // ---- lexical scope stack -------------------------------------------------

  private pushScope(): void {
    this.scopes.push(new Map());
  }
  private popScope(): void {
    this.scopes.pop();
  }
  private lookupLocal(name: string): JethType | undefined {
    for (let i = this.scopes.length - 1; i >= 0; i--) {
      const t = this.scopes[i]!.get(name);
      if (t) return t;
    }
    return undefined;
  }
  private isVisibleLocal(name: string): boolean {
    return this.lookupLocal(name) !== undefined;
  }
  private inCurrentScope(name: string): boolean {
    return this.scopes[this.scopes.length - 1]!.has(name);
  }
  private declareLocal(name: string, t: JethType): void {
    this.scopes[this.scopes.length - 1]!.set(name, t);
  }

  analyze(): ContractIR | undefined {
    this.rejectEmptyHexLiterals(); // lexer-level: `0x`/`0X` with no hex digits is a parse error in any context
    this.collectTypeAliases(); // branded newtypes, before structs (a struct field may use one)
    this.collectEnums(); // enums (branded uint8), before structs (a struct field / param may use one)
    this.collectStructs();
    this.collectInterfaces(); // @interface declarations: a named type + per-method ABI/selector registry
    this.collectLibraries(); // @library declarations: internal (inlined) functions, collected before contracts
    const classes = this.findContractClasses();
    if (classes.length === 0) {
      this.diags.error(this.sourceFile, 'JETH040', 'no @contract class found in source');
      return undefined;
    }
    if (classes.length > 1) {
      this.diags.error(classes[1]!, 'JETH041', 'multiple @contract classes per file are not supported in the MVP');
    }
    // Inheritance: register EVERY contract class (the deployed @contract + any @abstract bases) so the
    // C3 linearization can be resolved, then flatten the deployed contract's base chain into one merged
    // member ordering fed to the existing analyze/emit pipeline (only the @contract deploys).
    this.registerContractClasses();
    const lin = this.linearize(classes[0]!);
    if (!lin) return undefined; // a C3-impossible base order was reported
    return this.analyzeContract(classes[0]!, lin);
  }

  /** Collect `type X = Brand<BaseValueType>` branded-newtype aliases. A branded type is a
   *  distinct NOMINAL value type over its base (a zero-cost newtype): the brand is erased at
   *  codegen/ABI/selectors, so it is byte-identical to the base at runtime, but the type checker
   *  keeps it distinct (no implicit conversion to/from the base or another brand). Registered in
   *  structsByName so resolveType finds it; the struct-constructor dispatch ignores it (it is a
   *  value type, not kind 'struct'). */
  /** solc rejects a hexadecimal literal with no digits (`0x` or `0X`, optionally followed by
   *  underscores) as a parser error ("Hexadecimal digit missing or invalid") in EVERY context,
   *  including dead code and constant-folded sub-expressions. The TypeScript lexer instead
   *  normalizes such a literal to `0x0` in BigIntLiteral.text (parsing it as 0), so the emptiness
   *  is only visible in the original source spelling via getText(). This whole-source pre-pass
   *  walks every bigint literal and emits the error, matching solc's lexer. */
  private rejectEmptyHexLiterals(): void {
    const visit = (n: ts.Node): void => {
      if (ts.isBigIntLiteral(n) && /^0[xX]_*$/.test(n.getText().replace(/n$/, ''))) {
        this.diags.error(n, 'JETH049', `hexadecimal literal '0x' has no digits`);
      }
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(this.sourceFile, visit);
  }

  private collectTypeAliases(): void {
    const visit = (n: ts.Node): void => {
      if (ts.isTypeAliasDeclaration(n)) this.collectTypeAlias(n);
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(this.sourceFile, visit);
  }

  private collectTypeAlias(decl: ts.TypeAliasDeclaration): void {
    const name = decl.name.text;
    const t = decl.type;
    if (!ts.isTypeReferenceNode(t) || !ts.isIdentifier(t.typeName) || t.typeName.text !== 'Brand') {
      this.diags.error(
        decl,
        'JETH015',
        `type alias '${name}' must be 'Brand<BaseType>' (a distinct newtype over a value type)`,
      );
      return;
    }
    const args = t.typeArguments;
    if (!args || args.length !== 1) {
      this.diags.error(decl, 'JETH015', `Brand<...> takes exactly one base type, e.g. 'type ${name} = Brand<u256>'`);
      return;
    }
    const base = resolveType(args[0], this.diags, this.structsByName);
    if (!base) return;
    if (!isStaticValueType(base) || (base as { brand?: string }).brand) {
      this.diags.error(
        decl,
        'JETH015',
        `Brand<...> base must be a plain value type (u8..u256, i8..i256, bool, address, bytesN), got ${displayName(base)}`,
      );
      return;
    }
    if (this.structsByName.has(name) || resolvePrimitiveName(name)) {
      this.diags.error(decl, 'JETH015', `type name '${name}' conflicts with an existing type`);
      return;
    }
    this.structsByName.set(name, { ...base, brand: name } as JethType);
  }

  /** True if `name` is a registered branded newtype alias (so `Name(x)` is a wrap/unwrap cast). */
  private isBrandedAlias(name: string): boolean {
    const t = this.structsByName.get(name);
    return !!t && !!(t as { brand?: string }).brand;
  }

  /** Collect `enum Color { Red, Green, Blue }` declarations. An enum is modeled as a BRANDED
   *  uint8 carrying its member names: nominal identity is the brand, storage/ABI/codegen come
   *  from the uint8 base. Members are 0,1,2,... in declaration order and may NOT carry explicit
   *  values (solc enums are always 0-based and contiguous). Registered in structsByName so
   *  resolveType finds the type in field/param/return positions, exactly like a branded alias. */
  private collectEnums(): void {
    const visit = (n: ts.Node): void => {
      if (ts.isEnumDeclaration(n)) this.collectEnum(n);
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(this.sourceFile, visit);
  }

  private collectEnum(decl: ts.EnumDeclaration): void {
    const name = decl.name.text;
    if (this.structsByName.has(name) || resolvePrimitiveName(name)) {
      this.diags.error(decl, 'JETH272', `enum name '${name}' conflicts with an existing type`);
      return;
    }
    const members: string[] = [];
    for (const m of decl.members) {
      if (m.initializer) {
        this.diags.error(
          m,
          'JETH270',
          `enum members cannot have explicit values (member '${m.name.getText()}'); enum members are 0,1,2,... in declaration order`,
        );
        continue;
      }
      if (!ts.isIdentifier(m.name)) {
        this.diags.error(m, 'JETH273', 'enum member name must be a plain identifier');
        continue;
      }
      if (members.includes(m.name.text)) {
        this.diags.error(m, 'JETH274', `duplicate enum member '${m.name.text}' in '${name}'`);
        continue;
      }
      members.push(m.name.text);
    }
    if (members.length === 0) {
      this.diags.error(decl, 'JETH275', `enum '${name}' must have at least one member`);
      return;
    }
    if (members.length > 256) {
      this.diags.error(decl, 'JETH276', `enum '${name}' has ${members.length} members (max 256)`);
      return;
    }
    this.structsByName.set(name, { kind: 'uint', bits: 8, brand: name, enumMembers: members });
  }

  /** True if `name` is a registered enum type name (so `Name.Member` is a member constant and
   *  `Name(x)` is an integer -> enum range-checked conversion). */
  private isEnumName(name: string): boolean {
    const t = this.structsByName.get(name);
    return !!t && isEnum(t);
  }

  /** Resolve a TYPE written in VALUE position (the 2nd argument of abi.decode / the argument of
   *  `<bytes>.decode(T)`), reusing the same name resolution as a cast / type(T).max. Supported shapes:
   *  - a bare type name (u256/i128/bool/address/bytesN/bytes/string/an enum name/a branded newtype)
   *    -> the leaf JethType (an enum/branded resolves through structsByName, like checkCast);
   *  - `T[]` (an ElementAccessExpression with an EMPTY index, e.g. `u256[]`) -> a dynamic array;
   *  - `Arr<T, N>` (an ExpressionWithTypeArguments) -> a static fixed array (reuses resolveType so a
   *    nested element resolves identically to a declaration position).
   *  Returns undefined (no diagnostic) on an unrecognized shape; the caller emits the diagnostic. */
  private resolveTypeExpr(node: ts.Expression): JethType | undefined {
    // a bare type-name identifier
    if (ts.isIdentifier(node)) {
      return resolvePrimitiveName(node.text) ?? this.structsByName.get(node.text);
    }
    // `T[]`: an ElementAccessExpression whose base is a type-name and whose index is the synthetic
    // empty identifier produced by the parser for the `[]` suffix (TS emits a parse diagnostic the
    // compiler ignores; the AST is still walkable). -> a dynamic array of the resolved element type.
    if (
      ts.isElementAccessExpression(node) &&
      ts.isIdentifier(node.argumentExpression) &&
      node.argumentExpression.text === ''
    ) {
      const elem = this.resolveTypeExpr(node.expression);
      if (!elem) return undefined;
      return { kind: 'array', element: elem, length: undefined };
    }
    // `Arr<T, N>`: a generic type written in value position; reuse the canonical TypeNode resolver by
    // re-parsing the same text as a type (so `Arr<u256, 3>` / a nested element resolves identically to
    // a field/param position). The text is a syntactic type, so a TypeNode parse is exact.
    if (ts.isExpressionWithTypeArguments(node) || (ts.isCallExpression(node) && node.typeArguments)) {
      const typeNode = ts.factory.createTypeReferenceNode(
        (node.expression as ts.Identifier).text,
        (node as ts.ExpressionWithTypeArguments).typeArguments,
      );
      return resolveType(typeNode, this.diags, this.structsByName);
    }
    return undefined;
  }

  /** Collect @struct class declarations into the registry (in source order so a
   *  struct may reference earlier structs by value). */
  private collectStructs(): void {
    const visit = (n: ts.Node): void => {
      if (ts.isClassDeclaration(n) && decoratorNames(n).includes('struct')) this.collectStruct(n);
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(this.sourceFile, visit);
  }

  private collectStruct(cls: ts.ClassDeclaration): void {
    const name = cls.name?.text ?? 'Struct';
    if (this.structsByName.has(name)) {
      this.diags.error(cls, 'JETH220', `@struct '${name}' redeclared`);
      return;
    }
    const raw: RawStateVar[] = [];
    for (const member of cls.members) {
      if (!ts.isPropertyDeclaration(member)) continue;
      if (!ts.isIdentifier(member.name)) {
        this.diags.error(member, 'JETH221', 'struct field name must be a plain identifier');
        continue;
      }
      if (raw.some((r) => r.name === (member.name as ts.Identifier).text)) {
        this.diags.error(member, 'JETH221', `duplicate struct field name '${member.name.text}'`);
        continue;
      }
      const t = resolveType(member.type, this.diags, this.structsByName);
      if (!t) continue;
      // A mapping field (G7) is allowed: it makes the struct STORAGE-ONLY (the storage-only
      // gates below reject using it as a memory local / param / return / construction / copy,
      // matching Solidity). It occupies its own slot (planLayout); inner[k] resolves to
      // keccak(key . (structBase + fieldSlot)).
      if (t.kind === 'mapping') {
        raw.push({ name: member.name.text, type: t });
        continue;
      }
      // Fields may be static (value, nested struct, or fixed array). A struct with
      // >=1 dynamic field is itself dynamic (spec section 3) and supported as a
      // calldata param / return (Phase 4e-6). The supported dynamic field kinds are
      // bytes/string and a nested struct (which may itself be dynamic). A dynamic
      // ARRAY field (T[], string[], T[][]) inside a struct is still deferred (the
      // tuple codec would need an array-in-tuple tail walk we have not verified).
      if (!isStaticType(t) && !this.isSupportedDynStructField(t)) {
        this.diags.error(
          member,
          'JETH229',
          `struct field '${member.name.text}' of type ${displayName(t)} is not supported yet (supported dynamic field kinds: bytes/string and a nested struct)`,
        );
        continue;
      }
      raw.push({ name: member.name.text, type: t });
    }
    if (raw.length === 0) {
      this.diags.error(cls, 'JETH223', `@struct '${name}' must have at least one field`);
      return;
    }
    // struct-internal field layout reuses the state-var packing planner.
    const layout = planLayout(raw);
    const fields: StructField[] = layout.vars.map((v) => ({
      name: v.name,
      type: v.type,
      slot: v.slot,
      offset: v.offset,
    }));
    this.structsByName.set(name, { kind: 'struct', name, fields });
  }

  /** Collect @interface class declarations: a named type + a per-method {selector, mutability, params,
   *  return} registry. An @interface emits NO bytecode; its methods are BODYLESS and each requires
   *  @external (optional @view/@pure/@payable). Rejected (cleanly, no crash): a body, a @state field,
   *  a non-@external method, method overloading, and a constructor. */
  private collectInterfaces(): void {
    const visit = (n: ts.Node): void => {
      if (ts.isClassDeclaration(n) && decoratorNames(n).includes('interface')) this.collectInterface(n);
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(this.sourceFile, visit);
  }

  private collectInterface(cls: ts.ClassDeclaration): void {
    const name = cls.name?.text ?? 'Interface';
    if (this.interfacesByName.has(name) || this.structsByName.has(name)) {
      this.diags.error(cls, 'JETH340', `@interface '${name}' redeclared (the name is already a type)`);
      return;
    }
    const methods = new Map<string, InterfaceMethod>();
    for (const member of cls.members) {
      if (ts.isPropertyDeclaration(member)) {
        this.diags.error(member, 'JETH341', `@interface '${name}' cannot declare a field (an interface has no state)`);
        continue;
      }
      if (ts.isConstructorDeclaration(member)) {
        this.diags.error(member, 'JETH341', `@interface '${name}' cannot declare a constructor`);
        continue;
      }
      if (!ts.isMethodDeclaration(member)) {
        this.diags.error(member, 'JETH341', `@interface '${name}' may only declare bodyless @external methods`);
        continue;
      }
      const m = this.collectInterfaceMethod(member, name);
      if (!m) continue;
      if (methods.has(m.name)) {
        this.diags.error(
          member,
          'JETH342',
          `@interface '${name}' method '${m.name}' is overloaded; method overloading inside an interface is not supported yet`,
        );
        continue;
      }
      methods.set(m.name, m);
    }
    this.interfacesByName.set(name, { name, methods });
  }

  private collectInterfaceMethod(member: ts.MethodDeclaration, ifaceName: string): InterfaceMethod | undefined {
    if (!ts.isIdentifier(member.name)) {
      this.diags.error(member, 'JETH049', 'interface method name must be a plain identifier');
      return undefined;
    }
    const mname = member.name.text;
    const decs = decoratorNames(member);
    if (member.body) {
      this.diags.error(member, 'JETH343', `@interface method '${ifaceName}.${mname}' must be bodyless`);
      return undefined;
    }
    if (!decs.includes('external')) {
      this.diags.error(member, 'JETH344', `@interface method '${ifaceName}.${mname}' must be @external`);
      return undefined;
    }
    const explicitMuts = (['view', 'pure', 'payable'] as const).filter((m) => decs.includes(m));
    if (explicitMuts.length > 1) {
      this.diags.error(
        member,
        'JETH052',
        `@interface method '${ifaceName}.${mname}' has conflicting mutability decorators: ${explicitMuts.map((m) => '@' + m).join(', ')} (a method is at most one of @view/@pure/@payable)`,
      );
    }
    let mutability: Mutability = 'nonpayable';
    if (decs.includes('payable')) mutability = 'payable';
    else if (decs.includes('view')) mutability = 'view';
    else if (decs.includes('pure')) mutability = 'pure';
    const stray = decs.filter((d) => !['external', 'view', 'pure', 'payable'].includes(d));
    if (stray.length) {
      this.diags.error(
        member,
        'JETH345',
        `@interface method '${ifaceName}.${mname}' has unsupported decorator(s): ${stray.map((d) => '@' + d).join(', ')} (allowed: @external, @view, @pure, @payable)`,
      );
    }
    const params: Param[] = [];
    for (const p of member.parameters) {
      if (!ts.isIdentifier(p.name)) {
        this.diags.error(p, 'JETH053', 'parameter name must be a plain identifier');
        continue;
      }
      if (p.initializer) {
        this.diags.error(
          p,
          'JETH346',
          `@interface method '${ifaceName}.${mname}' parameter '${p.name.text}' cannot have a default value`,
        );
      }
      const t = resolveType(p.type, this.diags, this.structsByName);
      if (!t) continue;
      if (this.typeHasMapping(t)) {
        this.diags.error(
          p,
          'JETH247',
          `parameter '${p.name.text}' of type ${displayName(t)} contains a mapping and cannot be passed (mappings are storage-only)`,
        );
        continue;
      }
      // The arg encoding reuses the abi.encode codec; restrict params to types that codec supports so a
      // call never silently miscompiles (value types, bytes/string, supported arrays, structs).
      if (!this.interfaceAbiTypeSupported(t)) {
        this.diags.error(
          p,
          'JETH347',
          `@interface method '${ifaceName}.${mname}' parameter '${p.name.text}' has type ${displayName(t)}, which is not supported yet (supported: value types, bytes/string, value arrays, and structs of those)`,
        );
        continue;
      }
      params.push({ name: p.name.text, type: t });
    }
    // return: void, a single type, or a >=2-element tuple. Each component must be a decode-supported type.
    let returnType: JethType = VOID;
    let returnTypes: JethType[] | undefined;
    if (member.type && ts.isTupleTypeNode(member.type)) {
      const rts: JethType[] = [];
      for (const el of member.type.elements) {
        const t = resolveType(el, this.diags, this.structsByName);
        if (!t) continue;
        if (!this.decodeSupported(t)) {
          this.diags.error(
            el,
            'JETH348',
            `@interface method '${ifaceName}.${mname}' return component ${displayName(t)} is not supported yet (supported: value types, bytes/string, value arrays, and structs of those)`,
          );
          continue;
        }
        rts.push(t);
      }
      if (rts.length >= 2) returnTypes = rts;
      else if (rts.length === 1) returnType = rts[0]!;
    } else if (member.type) {
      const t = resolveType(member.type, this.diags, this.structsByName);
      if (t && t.kind !== 'void') {
        if (!this.decodeSupported(t)) {
          this.diags.error(
            member.type,
            'JETH348',
            `@interface method '${ifaceName}.${mname}' return type ${displayName(t)} is not supported yet (supported: value types, bytes/string, value arrays, and structs of those)`,
          );
        } else {
          returnType = t;
        }
      }
    }
    const signature = functionSignature(
      mname,
      params.map((p) => p.type),
    );
    const selector = functionSelector(signature);
    return { name: mname, params, returnType, returnTypes, mutability, signature, selector };
  }

  /** A type that the abi.encode arg codec supports for an interface call argument: value types,
   *  bytes/string, a value-element array (fixed or dynamic), or a struct. Mirrors checkAbiEncode's
   *  accepted arg shapes so a call never silently miscompiles. */
  private interfaceAbiTypeSupported(t: JethType): boolean {
    if (isStaticValueType(t) || isBytesLike(t)) return true;
    if (t.kind === 'array') return true; // standard abi.encode supports value/dyn arrays + fixed arrays
    if (t.kind === 'struct') return true; // static (inline) or dynamic (offset+tail) struct
    return false;
  }

  private findContractClasses(): ts.ClassDeclaration[] {
    const out: ts.ClassDeclaration[] = [];
    const visit = (n: ts.Node): void => {
      // Phase 2a: `@proxy class P` is a deployable contract too (the EIP-1967 upgradeable proxy). It is
      // the deployed @contract for this file (it needs no separate @contract decorator).
      if (ts.isClassDeclaration(n)) {
        const decs = decoratorNames(n);
        // Phase 2d: `@beacon class B` is a deployable contract too (the OZ UpgradeableBeacon-equivalent);
        // like @proxy it needs no separate @contract decorator.
        // Phase 3: `@facet class F` is a deployable contract too (it compiles to an ORDINARY contract -
        // own bytecode + selector dispatch; it may use @storage('ns') freely - and is deployed standalone
        // then cut into a diamond, like an external library). The only difference from @contract is the tag.
        if (decs.includes('contract') || decs.includes('proxy') || decs.includes('beacon') || decs.includes('facet'))
          out.push(n);
      }
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(this.sourceFile, visit);
    return out;
  }

  // ---- Phase A: internal (inlined) libraries --------------------------------

  /** Collect every `@library class L { ... }`. Each library's functions are gathered as ORDINARY
   *  internal functions (reusing collectFunction), but keyed by a QUALIFIED source name `L.f` (a `.`
   *  is illegal in a TS identifier, so a library function never collides with - nor is callable as -
   *  a contract function by bare name). They are registered into the contract's normal function
   *  machinery in analyzeContract, so they emit as `userfn_`s and flow through the purity fixpoint
   *  exactly like a contract internal function - byte-identical to solc's internal library functions.
   *  Gates (each a distinct diagnostic, never a crash): library state/immutable/constant fields, a
   *  constructor, an @external/@payable method, @receive/@fallback/@modifier, and inheritance. */
  private collectLibraries(): void {
    const visit = (n: ts.Node): void => {
      if (ts.isClassDeclaration(n) && decoratorNames(n).includes('library')) this.collectLibrary(n);
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(this.sourceFile, visit);
  }

  private collectLibrary(cls: ts.ClassDeclaration): void {
    const name = cls.name?.text ?? 'Library';
    // The library name shares the type/contract identifier namespace: a clash with a struct/enum/
    // interface/another library is a redeclaration (solc: "Identifier already declared").
    if (
      this.libraryByName.has(name) ||
      this.structsByName.has(name) ||
      this.interfacesByName.has(name) ||
      resolvePrimitiveName(name)
    ) {
      this.diags.error(cls, 'JETH386', `@library '${name}' redeclared (the name is already a type or library)`);
      return;
    }
    // A library has no inheritance in Phase A (solc forbids a library `is` clause entirely).
    if (heritageBases(cls).length > 0) {
      this.diags.error(
        cls,
        'JETH387',
        `@library '${name}' cannot extend another contract/library (libraries have no inheritance)`,
      );
    }
    const fns: RawFunction[] = [];
    for (const member of cls.members) {
      if (ts.isPropertyDeclaration(member)) {
        // @state / @immutable / @constant - a library has no storage and no baked-in fields.
        this.diags.error(
          member,
          'JETH388',
          `@library '${name}' cannot declare a field (a library has no state, immutable, or constant storage)`,
        );
        continue;
      }
      if (ts.isConstructorDeclaration(member)) {
        this.diags.error(member, 'JETH389', `@library '${name}' cannot declare a constructor`);
        continue;
      }
      if (ts.isGetAccessor(member) || ts.isSetAccessor(member)) {
        this.diags.error(member, 'JETH043', 'getters/setters are not supported');
        continue;
      }
      if (!ts.isMethodDeclaration(member)) continue;
      const decs = decoratorNames(member);
      // A library function is EITHER internal (inlined, Phase A) OR @external (delegatecall, Phase B).
      // @receive/@fallback are runtime entries with no place in a library; @payable is rejected because
      // a library delegatecall cannot carry value (solc: "Library functions cannot be payable.").
      const banned = (['payable', 'receive', 'fallback'] as const).find((d) => decs.includes(d));
      if (banned) {
        this.diags.error(
          member,
          'JETH390',
          banned === 'payable'
            ? `@library '${name}' method '${ts.isIdentifier(member.name) ? member.name.text : '<anon>'}' cannot be @payable (a library delegatecall cannot carry value)`
            : `@library '${name}' method '${ts.isIdentifier(member.name) ? member.name.text : '<anon>'}' cannot be @${banned} (a library has no runtime entry points)`,
        );
        continue;
      }
      const isExternal = decs.includes('external');
      // @modifier / @event / @error inside a library are not supported in Phase A (solc allows none
      // of these as a library's callable surface in the way JETH needs); keep the surface to plain
      // internal functions. Generic library functions are likewise deferred.
      if (decs.includes('modifier') || decs.includes('event') || decs.includes('error')) {
        this.diags.error(
          member,
          'JETH390',
          `@library '${name}' may only declare internal functions (no @modifier/@event/@error) in Phase A`,
        );
        continue;
      }
      if (member.typeParameters && member.typeParameters.length > 0) {
        this.diags.error(
          member,
          'JETH390',
          `@library '${name}' generic function is not supported in Phase A (a library function must be non-generic)`,
        );
        continue;
      }
      const fn = this.collectFunction(member);
      if (!fn) continue;
      // A library function needs an implementation (a bodyless method is meaningless: there is no
      // override/virtual surface for a library in Phase A).
      if (member.body === undefined) {
        this.diags.error(member, 'JETH390', `@library '${name}' method '${fn.name}' must have a body`);
        continue;
      }
      // A library function runs INLINED in the caller's context and has NO contract instance of its
      // own. `this.<member>` (a contract-state read/write `this.x`, or an internal contract call
      // `this.f()`) is meaningless in Phase A (a library scopes to value/memory/calldata params and
      // cannot touch contract state) and is rejected. Bare `this` (e.g. `address(this)` - the calling
      // contract's address) is LEFT alone: it is inlined, so it is byte-identical to solc, which also
      // accepts `address(this)` in a library function. msg.*/block.*/tx.* (NOT via `this`) likewise
      // remain legal - they read the caller's message context, exactly like a solc internal library
      // function. One body scan catches every `this.<member>` use.
      if (member.body) {
        const scanThis = (n: ts.Node): void => {
          if (ts.isPropertyAccessExpression(n) && n.expression.kind === ts.SyntaxKind.ThisKeyword) {
            this.diags.error(
              n,
              'JETH394',
              `@library '${name}' function '${ts.isIdentifier(member.name) ? member.name.text : '<anon>'}' cannot access 'this.${n.name.text}' (a library has no contract state or instance; pass values as parameters)`,
            );
          }
          ts.forEachChild(n, scanThis);
        };
        ts.forEachChild(member.body, scanThis);
      }
      // Re-key by the qualified source name `L.f`. This namespaces it away from every contract
      // function (and other libraries), keeps overloads grouped under the same qualified name (so the
      // existing overload resolver works), and makes the userfn_ / call-graph key unique.
      fn.name = `${name}.${fn.name}`;
      fn.libraryName = name;
      // Phase B: an @external library function is a DELEGATECALL entry (visibility 'external', dispatched
      // by selector in the library's own runtime object). An @view/@pure external library fn is still a
      // delegatecall (solc always delegatecalls a public/external library fn so it runs in the caller's
      // context). A bare external fn keeps its inferred mutability via the normal @read path.
      if (isExternal) {
        fn.libraryExternal = true;
        fn.visibility = 'external';
      }
      fns.push(fn);
    }
    this.libraryByName.set(name, fns);
  }

  /** True if `name` is a declared @library. */
  private isLibraryName(name: string): boolean {
    return this.libraryByName.has(name);
  }

  /** Build the `@using(L)` attachment map for the deployed contract: for each L in its @using
   *  decorators, attach every L function whose FIRST parameter type is T as a method on T, keyed by
   *  `${canonicalName(T)}#${methodName}` (the BARE method name, not the qualified `L.f`). More than
   *  one matching function for a (T, name) => ambiguous attachment (rejected at the call site). A
   *  function with zero parameters cannot attach (there is no receiver). An @using naming a
   *  non-library is rejected here. */
  private buildLibraryAttachments(cls: ts.ClassDeclaration): void {
    this.libraryAttachments.clear();
    const seen = new Set<string>();
    for (const d of ts.getDecorators(cls) ?? []) {
      const e = d.expression;
      if (!ts.isCallExpression(e) || !ts.isIdentifier(e.expression) || e.expression.text !== 'using') continue;
      for (const arg of e.arguments) {
        if (!ts.isIdentifier(arg)) {
          this.diags.error(arg, 'JETH391', `@using(...) argument must be a library name`);
          continue;
        }
        const libName = arg.text;
        if (!this.libraryByName.has(libName)) {
          this.diags.error(arg, 'JETH391', `@using(${libName}): '${libName}' is not a @library declared in this file`);
          continue;
        }
        if (seen.has(libName)) continue; // a duplicate @using(L) is harmless; attach once
        seen.add(libName);
        for (const fn of this.libraryByName.get(libName)!) {
          if (fn.params.length === 0) continue; // no receiver to attach on
          const t = fn.params[0]!.type;
          const bare = fn.name.slice(libName.length + 1); // strip the `L.` prefix
          const key = `${canonicalName(t)}#${bare}`;
          const list = this.libraryAttachments.get(key);
          if (list) list.push(fn);
          else this.libraryAttachments.set(key, [fn]);
        }
      }
    }
  }

  // ---- inheritance: contract registry + C3 linearization --------------------

  // All contract-like classes by name: the deployed @contract plus every @abstract base. Built
  // before flattening so a base reference in an `extends` clause resolves to its declaration.
  private classByName = new Map<string, ts.ClassDeclaration>();

  /** Register every `@contract`/`@abstract` class by name (for `extends` resolution). A `@contract`
   *  deploys; an `@abstract` is a non-deployable base. A class that is neither is ignored (the TS
   *  source may carry unrelated helper classes). JETH041 already forbids >1 `@contract`. */
  private registerContractClasses(): void {
    const visit = (n: ts.Node): void => {
      if (ts.isClassDeclaration(n) && n.name) {
        const decs = decoratorNames(n);
        if (decs.includes('contract') || decs.includes('abstract') || decs.includes('facet')) {
          this.classByName.set(n.name.text, n);
        }
      }
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(this.sourceFile, visit);
  }

  private isAbstractClass(cls: ts.ClassDeclaration): boolean {
    return decoratorNames(cls).includes('abstract');
  }

  /** C3-linearize the deployed contract's base hierarchy (most-derived FIRST). solc's MRO is
   *  Python C3 over the REVERSED `extends` lists with the contract prepended (so the LAST-listed
   *  base wins priority): `D is B, C` (B is A, C is A) -> [D, C, B, A]. A non-resolvable base name
   *  (JETH370) or an impossible merge (JETH371) is reported and undefined returned (the merged
   *  contract cannot be built). Detects a cyclic `extends` (JETH372). */
  private linearize(deployed: ts.ClassDeclaration): ts.ClassDeclaration[] | undefined {
    // Resolve a class's direct bases (in source order) to their declarations, reporting unknowns.
    const directBases = (cls: ts.ClassDeclaration): ts.ClassDeclaration[] | undefined => {
      const bases: ts.ClassDeclaration[] = [];
      for (const hb of heritageBases(cls)) {
        const b = this.classByName.get(hb.name);
        if (!b) {
          this.diags.error(
            hb.node,
            'JETH370',
            `base contract '${hb.name}' is not a @contract or @abstract class declared in this file`,
          );
          return undefined;
        }
        bases.push(b);
      }
      return bases;
    };

    const nameOf = (c: ts.ClassDeclaration) => c.name?.text ?? '<anon>';

    // Recursive C3 with cycle detection. `stack` tracks the in-progress chain for a clear cyclic
    // diagnostic; `memo` caches each class's linearization (a diamond's shared base is linearized once).
    const stack = new Set<string>();
    const memo = new Map<string, ts.ClassDeclaration[] | undefined>();
    const c3 = (cls: ts.ClassDeclaration): ts.ClassDeclaration[] | undefined => {
      const nm = nameOf(cls);
      if (memo.has(nm)) return memo.get(nm);
      if (stack.has(nm)) {
        this.diags.error(cls, 'JETH372', `cyclic contract inheritance involving '${nm}'`);
        return undefined;
      }
      stack.add(nm);
      const bases = directBases(cls);
      if (!bases) {
        stack.delete(nm);
        memo.set(nm, undefined);
        return undefined;
      }
      // L[cls] = cls + merge(L[B1], ..., L[Bn], [B1, ..., Bn]) where the bases are taken in REVERSED
      // source order (solc: rightmost base = highest priority). This matches solc's MRO direction.
      const revBases = [...bases].reverse();
      const seqs: ts.ClassDeclaration[][] = [];
      for (const b of revBases) {
        const lb = c3(b);
        if (!lb) {
          stack.delete(nm);
          memo.set(nm, undefined);
          return undefined;
        }
        seqs.push([...lb]);
      }
      seqs.push([...revBases]);
      const merged = this.c3Merge(cls, seqs);
      stack.delete(nm);
      if (!merged) {
        memo.set(nm, undefined);
        return undefined;
      }
      const result = [cls, ...merged];
      memo.set(nm, result);
      return result;
    };
    return c3(deployed);
  }

  /** Standard C3 merge: repeatedly take the head of the first sequence that appears in no other
   *  sequence's TAIL, remove it from every sequence, append it. A head blocked in every sequence
   *  means no consistent ordering exists -> JETH371 (matches solc's "Linearization of inheritance
   *  graph impossible"). Dedup is by class name. */
  private c3Merge(deployed: ts.ClassDeclaration, seqsIn: ts.ClassDeclaration[][]): ts.ClassDeclaration[] | undefined {
    const nameOf = (c: ts.ClassDeclaration) => c.name?.text ?? '<anon>';
    const seqs = seqsIn.map((s) => [...s]).filter((s) => s.length > 0);
    const out: ts.ClassDeclaration[] = [];
    while (seqs.some((s) => s.length > 0)) {
      let pick: ts.ClassDeclaration | undefined;
      for (const s of seqs) {
        if (s.length === 0) continue;
        const head = s[0]!;
        const hn = nameOf(head);
        const inTail = seqs.some((o) => o.slice(1).some((c) => nameOf(c) === hn));
        if (!inTail) {
          pick = head;
          break;
        }
      }
      if (!pick) {
        this.diags.error(
          deployed,
          'JETH371',
          `inheritance graph of '${nameOf(deployed)}' cannot be linearized (the base order is C3-inconsistent; reorder the bases so a more-derived contract precedes its bases)`,
        );
        return undefined;
      }
      const pn = nameOf(pick);
      out.push(pick);
      for (const s of seqs) {
        const i = s.findIndex((c) => nameOf(c) === pn);
        if (i >= 0) s.splice(i, 1);
      }
    }
    return out;
  }

  // Inheritance: per-contract constructors gathered while flattening (most-derived FIRST, matching
  // the linearization), each with its heritage base-call args. Consumed by mergeConstructors.
  private ctorChain: {
    contract: string;
    node?: ts.ConstructorDeclaration;
    bases: HeritageBase[];
    cls: ts.ClassDeclaration;
  }[] = [];

  private analyzeContract(cls: ts.ClassDeclaration, lin: ts.ClassDeclaration[]): ContractIR | undefined {
    const name = cls.name?.text ?? 'Contract';
    const rawState: RawStateVar[] = [];
    const rawFns: RawFunction[] = [];

    // ---- FLATTEN the C3 linearization into one merged member ordering ----
    // STATE: most-BASE first (REVERSE of the linearization), each contract's @state in declaration
    // order, fed as ONE flat list to planLayout with NO per-contract reset (packing carries across
    // the base/derived boundary, matching solc's storage layout). A same-name @state across the
    // chain is rejected (JETH373): JETH has no `private` state surface, so the solc private-shadow
    // exception cannot be expressed here.
    const stateOwner = new Map<string, string>(); // @state name -> declaring contract (collision check)
    for (const c of [...lin].reverse()) {
      const cn = c.name?.text ?? '<anon>';
      for (const member of c.members) {
        if (ts.isPropertyDeclaration(member) && ts.isIdentifier(member.name)) {
          const nm = member.name.text;
          const decs = decoratorNames(member);
          // only a plain @state takes a slot and can collide across the chain; @constant/@immutable
          // collisions are caught by the existing JETH046 path after collection.
          if (decs.includes('state') && !decs.includes('constant') && !decs.includes('immutable')) {
            const prior = stateOwner.get(nm);
            if (prior) {
              this.diags.error(
                member,
                'JETH373',
                `state variable '${nm}' is declared in both '${prior}' and '${cn}' (a same-name @state across an inheritance chain is not allowed; JETH has no private state-var shadowing)`,
              );
            }
            stateOwner.set(nm, cn);
          }
          this.collectStateVar(member, rawState);
        }
      }
    }

    // ERRORS / EVENTS / MODIFIERS / GENERICS: collected across ALL contracts in the linearization
    // (most-derived first) - merged into the single declaration tables (an inherited error/event/
    // modifier is usable in the derived contract). Decl order does not affect their semantics.
    // FUNCTIONS: collected per defining contract, tagged with definingContract, then run through
    // override resolution below (winner = most-derived; non-winners become per-contract super targets).
    // Phase 6: @receive / @fallback special entries. The C3 linearization is most-derived-FIRST, so the
    // FIRST one seen for each kind is the override winner. A second one in a MORE-BASE contract is the
    // overridden base version (ignored); a second in the SAME contract is an error (JETH383).
    let receiveNode: { member: ts.MethodDeclaration; contract: string } | undefined;
    let fallbackNode: { member: ts.MethodDeclaration; contract: string } | undefined;
    const collectedFns: RawFunction[] = [];
    for (const c of lin) {
      const cn = c.name?.text ?? '<anon>';
      let ctorNode: ts.ConstructorDeclaration | undefined;
      let sawReceiveHere = false;
      let sawFallbackHere = false;
      for (const member of c.members) {
        if (ts.isMethodDeclaration(member)) {
          const decs = decoratorNames(member);
          if (decs.includes('receive')) {
            if (sawReceiveHere)
              this.diags.error(member, 'JETH383', 'a contract may declare at most one @receive entry');
            sawReceiveHere = true;
            if (!receiveNode) receiveNode = { member, contract: cn };
            continue;
          }
          if (decs.includes('fallback')) {
            if (sawFallbackHere)
              this.diags.error(member, 'JETH383', 'a contract may declare at most one @fallback entry');
            sawFallbackHere = true;
            if (!fallbackNode) fallbackNode = { member, contract: cn };
            continue;
          }
          if (decs.includes('error')) this.collectErrorDecl(member);
          else if (decs.includes('event')) this.collectEvent(member);
          else if (decs.includes('modifier')) this.collectModifier(member);
          else if (member.typeParameters && member.typeParameters.length > 0) {
            // F6: a generic function template - registered for monomorphization (not inherited-keyed;
            // generics are internal-only and not part of the override surface).
            this.collectGeneric(member);
          } else {
            const fn = this.collectFunction(member);
            if (fn) {
              fn.definingContract = cn;
              collectedFns.push(fn);
            }
          }
        } else if (ts.isConstructorDeclaration(member)) {
          if (ctorNode) this.diags.error(member, 'JETH300', 'a contract may declare at most one constructor');
          else ctorNode = member;
        } else if (ts.isGetAccessor(member) || ts.isSetAccessor(member)) {
          this.diags.error(member, 'JETH043', 'getters/setters are not supported');
        }
        // a PropertyDeclaration was already handled in the state pass above.
      }
      this.ctorChain.push({ contract: cn, node: ctorNode, bases: heritageBases(c), cls: c });
    }

    // Resolve overrides: the winner per (name + param types) is the most-derived definition; it keeps
    // the bare ABI key/selector and is dispatched. Non-winning base versions are kept ONLY as `super`
    // targets, re-keyed `<Contract>__<name>`. Enforces all virtual/override/list/return/mutability/
    // visibility rules. Returns the function list to feed the existing register/check pipeline.
    rawFns.push(...this.resolveOverrides(lin, collectedFns));

    // Phase A: register every @library's functions as ordinary internal functions of THIS compile.
    // They were collected with a qualified source name `L.f` (namespaced away from contract names),
    // so they flow through the same candidatesByName / key-assignment / checkFunction / purity-fixpoint
    // / FunctionIR-emission pipeline as a contract internal function and emit as `userfn_`s - making
    // `L.f(args)` and an attached `x.f(args)` byte-identical to solc's internal library functions.
    for (const fns of this.libraryByName.values()) rawFns.push(...fns);
    // Build the `@using(L)` attachment map for the deployed contract (so `x.f(args)` can desugar to
    // `L.f(x, ...args)`); also validates each @using names a real library.
    this.buildLibraryAttachments(cls);

    // Plan storage layout, then build the symbol table. The planner lays @state out from slot 0
    // sequentially (small number slots); widen each to a `bigint` StateVar.slot here so every
    // downstream IR base-slot field is bigint (Part A). @storage('ns') namespaced fields are then
    // appended at their ERC-7201 keccak bases (Part B), in a DISJOINT slot space.
    const layout = planLayout(rawState);
    const stateVars: StateVar[] = layout.vars.map((v) => ({
      name: v.name,
      type: v.type,
      slot: BigInt(v.slot),
      offset: v.offset,
      initialValue: v.initialValue,
    }));
    // Part B: lay out each @storage('ns') namespace and append its fields at base(ns)+relativeSlot.
    stateVars.push(...this.planNamespacedStorage());
    for (const v of stateVars) this.stateByName.set(v.name, v);

    // An @immutable name must not collide with a @state var or @constant (solc: duplicate
    // identifier). collectImmutable cannot see @state names yet (planned only here), so check now.
    for (const name of this.immutableOrder) {
      if (this.stateByName.has(name) || this.constantsByName.has(name)) {
        this.diags.error(
          cls,
          'JETH046',
          `field name '${name}' is declared more than once (@immutable conflicts with a @state/@constant of the same name)`,
        );
      }
    }

    // Register functions by name BEFORE checking bodies so an internal call can
    // forward-reference a callee declared later (matches Solidity). funcsByName keeps the FIRST
    // function per source name (for "is this name callable?" checks + the generic mangled-name
    // namespace); candidatesByName holds ALL overloads for resolution at the call site.
    for (const rf of rawFns) {
      const list = this.candidatesByName.get(rf.name);
      if (list) list.push(rf);
      else this.candidatesByName.set(rf.name, [rf]);
      if (!this.funcsByName.has(rf.name)) this.funcsByName.set(rf.name, rf);
    }

    // Cross-kind identifier collision (solc: "Identifier already declared"). Every contract-level
    // declaration shares one identifier namespace; a name may carry MULTIPLE declarations ONLY if
    // they are all functions (overloading) or all events (overloading). A name used by two DIFFERENT
    // kinds - function / event / error / type (struct or enum) / storage (state/@constant/@immutable)
    // - collides. Intra-kind duplicates are handled elsewhere (JETH046 immutable, JETH128 error,
    // JETH272 enum/struct, the overload resolver), so this only catches cross-kind reuse.
    const idKinds = new Map<string, Set<string>>();
    const addId = (nm: string, kind: string): void => {
      const s = idKinds.get(nm) ?? new Set<string>();
      s.add(kind);
      idKinds.set(nm, s);
    };
    for (const nm of this.candidatesByName.keys()) addId(nm, 'function');
    for (const nm of this.genericsByName.keys()) addId(nm, 'function');
    for (const nm of this.eventsByName.keys()) addId(nm, 'event');
    for (const nm of this.errorsByName.keys()) addId(nm, 'error');
    for (const nm of this.structsByName.keys()) addId(nm, 'type'); // structs + enums share the type namespace
    for (const nm of this.interfacesByName.keys()) addId(nm, 'type'); // interfaces share the type namespace too
    for (const v of stateVars) addId(v.name, 'storage');
    for (const nm of this.constantsByName.keys()) addId(nm, 'storage');
    for (const nm of this.immutableOrder) addId(nm, 'storage');
    for (const [nm, kinds] of idKinds) {
      if (kinds.size > 1) {
        this.diags.error(
          cls,
          'JETH133',
          `identifier '${nm}' is already declared (a ${[...kinds].join(' and a ')} share the name; solc reuses a name only among overloaded functions or events)`,
        );
      }
    }
    // Assign each function a UNIQUE key: the bare name when that name is unique, else `name__ovN`
    // (decl order). This keys the effects map / Yul `userfn_` name / call-graph identity so two
    // overloads never collide. Solc allows overloading by arity or parameter types.
    for (const [nm, list] of this.candidatesByName) {
      if (list.length > 1)
        list.forEach((rf, i) => {
          rf.key = `${nm}__ov${i}`;
        });
    }

    // Inheritance: now that the WINNER keys are assigned, resolve each super-resolution chain's head
    // (the winner) to its real key. resolveOverrides stored the winner RawFunction in winnerRef.
    for (const chain of this.overrideChains.values()) {
      const head = chain[0];
      if (head && head.winnerRef) head.key = this.fkey(head.winnerRef);
    }

    // Type-check each function body, capturing each function's DIRECT effects and its
    // internal callees for the transitive-purity fixpoint below.
    const functions: FunctionIR[] = [];
    const effects = new Map<
      string,
      { writes: boolean; reads: boolean; readsEnv: boolean; callees: Set<string>; rf: RawFunction }
    >();
    for (const rf of rawFns) {
      const f = this.checkFunction(rf);
      if (f) {
        if (rf.definingContract) f.definingContract = rf.definingContract;
        functions.push(f);
        effects.set(this.fkey(rf), {
          writes: this.currentWritesState,
          reads: this.currentReadsState,
          readsEnv: this.currentReadsEnv,
          callees: this.currentCallees,
          rf,
        });
      }
    }

    // Inheritance: check the non-winning base function versions kept as `super` targets. They are
    // forced-internal (emitted as userfn_<key>, reachable only via super), so they carry their own
    // effects into the purity fixpoint. The CURRENT defining contract is set so a super.f() inside a
    // super target resolves up its own chain.
    for (const rf of this.superTargets) {
      const f = this.checkFunction(rf);
      if (f) {
        f.definingContract = rf.definingContract;
        f.internallyCalled = true; // emit the userfn even if never internally referenced yet
        functions.push(f);
        effects.set(this.fkey(rf), {
          writes: this.currentWritesState,
          reads: this.currentReadsState,
          readsEnv: this.currentReadsEnv,
          callees: this.currentCallees,
          rf,
        });
      }
    }

    // F6: drain the specialization worklist. Checking a body may have queued generic
    // specializations, and a specialization's own body may queue MORE (a generic calling another
    // generic, or recursing at a new type), so loop until the queue is empty. The mangled name is
    // already in funcsByName + specializedNames (registered when the call was first seen), so a
    // recursive self-call at the same T resolves to the in-progress specialization instead of
    // re-queuing it. Each specialization's effects feed the same transitive-purity fixpoint below.
    while (this.specializationQueue.length > 0) {
      const spec = this.specializationQueue.shift()!;
      const rf = this.funcsByName.get(spec.mangled)!;
      this.withTypeBinding(spec.binding, () => {
        const f = this.checkFunction(rf);
        if (f) {
          functions.push(f);
          effects.set(this.fkey(rf), {
            writes: this.currentWritesState,
            reads: this.currentReadsState,
            readsEnv: this.currentReadsEnv,
            callees: this.currentCallees,
            rf,
          });
        }
      });
    }

    // Transitive purity: a function inherits the state/env effects of everything it calls.
    // Fixpoint over the call graph (handles recursion / mutual recursion), then validate
    // each declared mutability against the TRANSITIVE effects (matches solc, which rejects
    // e.g. a @view function that calls a state-writing helper).
    let changed = true;
    while (changed) {
      changed = false;
      for (const e of effects.values()) {
        for (const callee of e.callees) {
          const ce = effects.get(callee);
          if (!ce) continue;
          if (ce.writes && !e.writes) {
            e.writes = true;
            changed = true;
          }
          if (ce.reads && !e.reads) {
            e.reads = true;
            changed = true;
          }
          if (ce.readsEnv && !e.readsEnv) {
            e.readsEnv = true;
            changed = true;
          }
        }
      }
    }
    for (const e of effects.values()) {
      if (e.rf.inferRead) {
        // @read is read-only: a transitive state modification (storage write or emit) is an error;
        // @pure/@view is assigned below.
        if (e.writes)
          this.diags.error(
            e.rf.node,
            'JETH056',
            `@read function '${e.rf.name}' must not modify state (write to storage or emit an event) - it is read-only`,
          );
        continue;
      }
      if (e.rf.mutability === 'view' && e.writes)
        this.diags.error(
          e.rf.node,
          'JETH054',
          `@view function '${e.rf.name}' modifies state (writes to storage or emits an event)`,
        );
      if (e.rf.mutability === 'pure' && (e.writes || e.reads))
        this.diags.error(
          e.rf.node,
          'JETH055',
          `@pure function '${e.rf.name}' accesses state (storage or emits an event)`,
        );
      if (e.rf.mutability === 'pure' && e.readsEnv)
        this.diags.error(
          e.rf.node,
          'JETH164',
          `@pure function '${e.rf.name}' reads the execution environment (msg.*/block.*/tx.*/address(this))`,
        );
    }
    // RESOLVE inference (mutability + visibility) from the transitive effects + call graph, then
    // mark internally-called functions. After this the FunctionIR carries concrete visibility +
    // mutability, so the ABI emitter and dispatcher (which read these) produce the TRUE ABI.
    for (const f of functions) {
      const e = effects.get(f.key);
      if (e?.rf.inferRead) {
        const m: Mutability = e.reads || e.readsEnv ? 'view' : 'pure';
        f.mutability = m;
        e.rf.mutability = m;
      }
      if (this.internallyCalled.has(f.key)) f.internallyCalled = true;
    }

    // Auto-generate getters for @public state variables (solc parity). A value-type or bytes/string
    // getter is `name() view returns (T)` reading the slot directly. Mapping/array getters are
    // PARAMETERIZED in solc: each mapping level adds a key param and each array level a uint256 index
    // param, returning the leaf value (`name(K..,uint256..) -> leaf`). Struct leaves (which solc
    // flattens into a value-field tuple) and a few nested combinations are not yet supported and are
    // rejected cleanly rather than silently producing no getter. Inserted before the selector-clash
    // check so a getter colliding with a same-named function is a clean JETH044 error (matches solc).
    for (const v of stateVars) {
      if (!this.publicStateNames.has(v.name)) continue;
      const getter = this.synthPublicGetter(v);
      if (!getter) {
        this.diags.error(
          cls,
          'JETH057',
          `@public getter for state variable '${v.name}' of type ${displayName(v.type)} is not supported yet (declare an explicit @view getter)`,
        );
        continue;
      }
      functions.push(getter);
    }

    // Auto-generate a view getter for each `@external @immutable` field (solc's `public immutable`
    // auto-getter). `name() view returns (T)` returns the immutable via loadimmutable (a code read,
    // NO storage slot). Inserted BEFORE the selector-clash check so a getter colliding with a
    // same-named function is a clean JETH044 (matches solc). The selector is keccak(name+"()")[:4].
    for (const name of this.immutableOrder) {
      if (!this.publicImmutableNames.has(name)) continue;
      functions.push(this.synthImmutableGetter(this.immutablesByName.get(name)!));
    }

    // Phase 2c (UUPS): `@uups @contract` synthesizes upgradeToAndCall(address,bytes) + proxiableUUID()
    // BEFORE the selector-clash check, so a user-declared upgradeToAndCall/proxiableUUID clashes via the
    // normal JETH044 path. Validates the user `authorizeUpgrade(address)` gate exists and marks it
    // internally-called (so its userfn_ is emitted for the synthesized entry to call).
    const isUups = decoratorNames(cls).includes('uups');
    if (isUups) this.synthesizeUups(cls, decoratorNames(cls).includes('proxy'), rawFns, functions);

    // Phase 2d (BEACON): `@beacon class B` synthesizes the OZ UpgradeableBeacon 5.x surface - three
    // @external entries (upgradeTo(address), implementation(), owner()) plus a hand-written creation
    // (emitted in yul) - BEFORE the selector-clash check so a user-declared clash hits the normal path.
    const isBeacon = decoratorNames(cls).includes('beacon');
    if (isBeacon) this.synthesizeBeacon(cls, functions, layout.vars.length, !!receiveNode, !!fallbackNode);

    // Reject duplicate selectors (would make a dispatcher ambiguous). The CONTRACT dispatcher and each
    // external LIBRARY object have INDEPENDENT selector spaces (separate Yul objects), so a library
    // external function (its selector is the bare `f(...)`) is checked within its own library, never
    // against the contract. A library function's source name is qualified `L.f`.
    const libNameOf = (f: FunctionIR): string | undefined => {
      const dot = f.name.indexOf('.');
      return dot > 0 && this.libraryByName.has(f.name.slice(0, dot)) ? f.name.slice(0, dot) : undefined;
    };
    const seen = new Map<string, string>(); // contract dispatcher selector space
    const libSeen = new Map<string, Map<string, string>>(); // per-library selector space (external fns)
    for (const f of functions) {
      if (f.visibility === 'internal' || f.visibility === 'private') continue;
      const lib = libNameOf(f);
      const space = lib ? (libSeen.get(lib) ?? new Map<string, string>()) : seen;
      if (lib) libSeen.set(lib, space);
      const prev = space.get(f.selector);
      if (prev) {
        this.diags.error(cls, 'JETH044', `selector clash 0x${f.selector} between ${prev} and ${f.signature}`);
      } else space.set(f.selector, f.signature);
    }
    // Reject duplicate function SIGNATURES (name + parameter types) across ALL functions, including
    // internal/private and across visibilities - solc forbids two functions with the same name and
    // parameter types (a differing return type does not disambiguate). Distinct param types are valid
    // overloads (#47), so they have distinct signatures and are not flagged.
    // Key by (defining contract, signature): two same-signature functions in ONE contract are a real
    // duplicate, but the same signature across an inheritance chain is OVERRIDING (the override winner
    // and the per-contract `super` targets legitimately share a signature) - not a duplicate.
    const internalSig = (f: FunctionIR) =>
      `${f.definingContract ?? ''}::${f.name}(${f.params.map((p) => `${canonicalName(p.type)}|${displayName(p.type)}`).join(',')})`;
    const seenSig = new Map<string, boolean>();
    for (const f of functions) {
      const isig = internalSig(f);
      if (seenSig.has(isig)) {
        this.diags.error(
          cls,
          'JETH044',
          `duplicate function '${f.signature}' (a function with the same name and parameter types is already declared)`,
        );
      } else seenSig.set(isig, true);
    }

    // Phase 5 + inheritance: build the single merged constructor now that the state symbol table and
    // function registry exist. mergeConstructors encodes the two-phase order across the base chain:
    // PHASE 1 evaluates all base-ctor ARGUMENT expressions most-DERIVED-first (binding each base's
    // params), PHASE 2 runs the ctor bodies most-BASE-first. @immutable inline initializers stage at
    // the start (solc parity). With no constructor anywhere and no inline immutable init, no ctor.
    const ctor = this.mergeConstructors();

    // Phase 6: type-check the @receive / @fallback bodies now that the symbol tables exist (a constructor-
    // like context). The most-derived definition won during collection above.
    const receive = receiveNode ? this.checkSpecialEntry(receiveNode.member, 'receive') : undefined;
    const fallback = fallbackNode ? this.checkSpecialEntry(fallbackNode.member, 'fallback') : undefined;

    // Phase 2a: `@proxy class P` -> the EIP-1967 upgradeable-proxy foundation. JETH synthesizes the
    // canonical delegate fallback (forward ALL calldata to the EIP-1967 impl slot) in the runtime
    // fallback position. The proxy has no storage of its own (it lives in the impl) and may NOT declare
    // a user @receive/@fallback (the synthesized fallback owns that position).
    const isProxy = decoratorNames(cls).includes('proxy');
    // Phase 2b: a variant argument on `@proxy(...)`. `@proxy('transparent')` -> the OZ
    // TransparentUpgradeableProxy-equivalent (caller-routed fallback, synthesized below in yul). A bare
    // `@proxy` (or `@proxy()`) is the plain Phase-2a delegate-only proxy. Any other argument is rejected.
    let proxyVariant: 'transparent' | 'beacon' | undefined;
    if (isProxy) {
      const call = decoratorCall(cls, 'proxy');
      if (call && call.arguments.length > 0) {
        if (call.arguments.length !== 1) {
          this.diags.error(
            call,
            'JETH400',
            "@proxy(...) takes at most one variant argument (a string literal, e.g. @proxy('transparent') or @proxy('beacon'))",
          );
        } else {
          const arg = call.arguments[0]!;
          const variant = ts.isStringLiteralLike(arg) ? arg.text : undefined;
          if (variant === 'transparent') proxyVariant = 'transparent';
          else if (variant === 'beacon') proxyVariant = 'beacon';
          else
            this.diags.error(
              arg,
              'JETH400',
              `unknown @proxy variant ${ts.isStringLiteralLike(arg) ? `'${arg.text}'` : 'argument'} (only 'transparent' and 'beacon' are supported; omit the argument for the plain delegate-only proxy)`,
            );
        }
      }
      if (receiveNode)
        this.diags.error(
          receiveNode.member,
          'JETH398',
          'a @proxy class may not declare a @receive entry (the delegate fallback is synthesized)',
        );
      if (fallbackNode)
        this.diags.error(
          fallbackNode.member,
          'JETH398',
          'a @proxy class may not declare a @fallback entry (the delegate fallback is synthesized)',
        );
      if (layout.vars.length > 0)
        this.diags.error(
          cls,
          'JETH399',
          'a @proxy class may not declare @state (proxy storage belongs to the implementation; use proxyInit/upgradeProxy for the EIP-1967 slots)',
        );
      // Phase 2b: a transparent proxy exposes NO own functions to non-admins (every non-admin call
      // delegates to the impl; an admin may ONLY call upgradeToAndCall, which the synthesized fallback
      // handles). So an @external method on the contract is unreachable AND clashes the impl's selectors.
      if (proxyVariant === 'transparent') {
        for (const f of functions) {
          if (f.visibility === 'external') {
            this.diags.error(
              cls,
              'JETH401',
              `a @proxy('transparent') class may not declare an @external method ('${f.signature}'): every non-admin call delegates to the implementation and the admin may only call upgradeToAndCall (the upgrade entry is synthesized)`,
            );
          }
        }
      }
      // Phase 2d: a beacon proxy is delegate-only (every call resolves the impl via the beacon and
      // delegatecalls). It exposes NO own functions - the user writes only the constructor (proxyInitBeacon).
      // An @external method would be unreachable behind the synthesized delegate fallback, so reject it.
      if (proxyVariant === 'beacon') {
        for (const f of functions) {
          if (f.visibility === 'external') {
            this.diags.error(
              cls,
              'JETH405',
              `a @proxy('beacon') class may not declare an @external method ('${f.signature}'): every call resolves the implementation via the beacon and delegates to it (the user writes only the constructor with proxyInitBeacon)`,
            );
          }
        }
      }
    }

    // Phase B: partition out external (delegatecall) libraries. A library's @external functions are
    // delegatecall entry points emitted in the LIBRARY's own object (NEVER the contract dispatcher); a
    // library function reachable ONLY from such an external entry belongs to the library object, not the
    // contract (solc would never bake a library-only function into the contract). A library INTERNAL
    // function the CONTRACT inlines (Phase A) stays in the contract and is ALSO duplicated into the
    // library object if a library-external fn calls it (Yul scopes userfn_s per object, so the same key
    // in two objects is fine). Only libraries actually referenced via a delegatecall site are emitted.
    const callGraph = new Map<string, Set<string>>();
    for (const [k, e] of effects) callGraph.set(k, e.callees);
    const libraries = this.partitionExternalLibraries(functions, callGraph);
    // Any library declaring an @external function changes the contract function set: such a function is
    // a delegatecall entry (NOT a contract dispatcher entry), and any library function reachable only
    // from one of them belongs to the library object, never the contract. This holds even for an
    // UNREFERENCED external library (no link site) - it must still not pollute the contract dispatcher.
    const hasAnyExternalLibFn = [...this.libraryByName.values()].some((fns) => fns.some((rf) => rf.libraryExternal));
    const contractFunctions = hasAnyExternalLibFn ? this.contractRetainedFunctions(functions, callGraph) : functions;

    return {
      name,
      stateVars,
      functions: contractFunctions,
      errors: this.errors,
      events: this.events,
      slotCount: layout.slotCount,
      ctor,
      immutables: this.immutableOrder.map((n) => ({ name: n, type: this.immutablesByName.get(n)!.type })),
      receive,
      fallback,
      isProxy,
      proxyVariant,
      isUups: isUups || undefined,
      isBeacon: isBeacon || undefined,
      isDiamond: this.diamond ? true : undefined,
      diamondVariant: this.diamond?.variant,
      // The router looks up the selector->facet mapping at its actual planned slot. That mapping is the
      // FIRST field of the diamond's selector-storage namespace: `_sel2facet` (array model) or `_facets`
      // (packed / solidstate). For the array+packed models the namespace base = keccak256(mudgen string),
      // so the field lands at base+0; for solidstate the field lives at the (different) DiamondBase
      // namespace base+0. Resolving by name yields the correct slot for every model.
      diamondStorageBase: this.diamond ? BigInt('0x' + toHex(keccak('diamond.standard.diamond.storage'))) : undefined,
      diamondSel2FacetSlot: this.diamond
        ? (this.stateByName.get('_sel2facet')?.slot ??
          this.stateByName.get('_facets')?.slot ??
          BigInt('0x' + toHex(keccak('diamond.standard.diamond.storage'))))
        : undefined,
      libraries: libraries.length > 0 ? libraries : undefined,
    };
  }

  /** Phase 2c (UUPS): synthesize the two @external entries of a `@uups @contract` (byte-identical to OZ
   *  UUPSUpgradeable 5.x):
   *   - upgradeToAndCall(address newImpl, bytes data): payable. Calls the user gate authorizeUpgrade(newImpl),
   *     then the anti-brick proxiableUUID staticcall on newImpl (revert ERC1967InvalidImplementation on a
   *     failed staticcall; revert UUPSUnsupportedProxiableUUID on a wrong slot), then the EIP-1967 upgrade
   *     (sstore impl slot, emit Upgraded(indexed), data delegatecall+bubble). yul.ts emits the body.
   *   - proxiableUUID(): view returns bytes32. Returns the EIP-1967 impl slot constant.
   *  Gates: @uups requires a bare internal/private `authorizeUpgrade(newImpl: address): void`; rejects
   *  @uups + @proxy on one class; rejects a user-declared upgradeToAndCall/proxiableUUID (clash). The two
   *  synthesized FunctionIRs are pushed into `functions` (ordinary dispatcher entries). */
  private synthesizeUups(
    cls: ts.ClassDeclaration,
    alsoProxy: boolean,
    rawFns: RawFunction[],
    functions: FunctionIR[],
  ): void {
    // @uups marks an IMPLEMENTATION contract; it is mutually exclusive with @proxy (the proxy used with a
    // UUPS impl is the plain Phase-2a @proxy, a SEPARATE contract).
    if (alsoProxy) {
      this.diags.error(
        cls,
        'JETH404',
        '@uups may not be combined with @proxy (a UUPS implementation is a normal @contract; the proxy deployed against it is the plain @proxy)',
      );
      return;
    }
    // The user MUST declare the upgrade gate `authorizeUpgrade(newImpl: address)` (internal/private, void,
    // exactly one address param). OZ's `_authorizeUpgrade(address)` is abstract and the integrator MUST
    // implement it; without it the upgrade is ungated (a brick risk), so reject @uups outright.
    const candidates = this.candidatesByName.get('authorizeUpgrade') ?? [];
    const gate = candidates.find(
      (rf) =>
        (rf.visibility === 'internal' || rf.visibility === 'private') &&
        rf.params.length === 1 &&
        rf.params[0]!.type.kind === 'address' &&
        rf.returnType.kind === 'void' &&
        !rf.returnTypes,
    );
    if (!gate) {
      this.diags.error(
        cls,
        'JETH402',
        "a @uups contract must declare an internal upgrade gate 'authorizeUpgrade(newImpl: address): void' (the access check run before every upgrade; declare it @internal/@private)",
      );
      return;
    }
    // The synthesized selectors clash with a user-declared function of the same signature - reject early
    // with a clear message (the generic JETH044 below would also catch it, but this is more precise).
    for (const sig of ['upgradeToAndCall(address,bytes)', 'proxiableUUID()']) {
      const name = sig.slice(0, sig.indexOf('('));
      if ((this.candidatesByName.get(name) ?? []).length > 0) {
        this.diags.error(
          cls,
          'JETH403',
          `a @uups contract may not declare '${name}' (the ${sig} entry is synthesized by @uups)`,
        );
        return;
      }
    }
    // The gate is reached only from the synthesized upgradeToAndCall body, so force-emit its userfn_.
    // The internallyCalled SWEEP over `functions` already ran above, so set the FunctionIR flag directly
    // (the gate's checked FunctionIR is already in `functions`) AND add the key to the set for symmetry.
    const gateKey = this.fkey(gate);
    this.internallyCalled.add(gateKey);
    const gateFn = functions.find((f) => f.key === gateKey);
    if (gateFn) gateFn.internallyCalled = true;
    const BYTES32: JethType = { kind: 'bytesN', size: 32 };
    // upgradeToAndCall(address,bytes): payable (OZ `public payable`). body is empty (yul.ts emits it).
    const upgradeSig = functionSignature('upgradeToAndCall', [ADDRESS, BYTES]);
    functions.push({
      name: 'upgradeToAndCall',
      key: 'upgradeToAndCall',
      visibility: 'external',
      mutability: 'payable',
      params: [
        { name: 'newImplementation', type: ADDRESS },
        { name: 'data', type: BYTES },
      ],
      returnType: VOID,
      signature: upgradeSig,
      selector: functionSelector(upgradeSig),
      body: [],
      uupsKind: 'upgradeToAndCall',
      authorizeKey: this.fkey(gate),
    });
    // proxiableUUID(): view returns bytes32 (OZ `external view`).
    const proxiableSig = functionSignature('proxiableUUID', []);
    functions.push({
      name: 'proxiableUUID',
      key: 'proxiableUUID',
      visibility: 'external',
      mutability: 'view',
      params: [],
      returnType: BYTES32,
      signature: proxiableSig,
      selector: functionSelector(proxiableSig),
      body: [],
      uupsKind: 'proxiableUUID',
    });
  }

  /** Phase 2d (BEACON): synthesize the OpenZeppelin UpgradeableBeacon 5.x surface for a `@beacon class B`.
   *  JETH generates the ENTIRE boilerplate so the user writes only `@beacon class B { constructor(impl:
   *  address) {} }`:
   *   - a hand-written creation (emitted in yul): owner = msg.sender at storage slot 0 (OZ Ownable._owner
   *     layout); require(isContract(impl)); store impl at slot 1; emit Upgraded(indexed impl).
   *   - upgradeTo(address newImpl): owner-gated (revert OwnableUnauthorizedAccount on a non-owner caller);
   *     require(isContract(newImpl)); store slot 1; emit Upgraded(indexed newImpl). -> void.
   *   - implementation(): view returns address - SLOAD slot 1.
   *   - owner(): view returns address - SLOAD slot 0.
   *  Gates (each a distinct JETH40x, never a crash): @beacon may not declare @state/@constant/@immutable
   *  (fixed slots 0/1 are reserved), a @receive/@fallback, inheritance, or a clashing upgradeTo/implementation/
   *  owner; it MUST declare `constructor(impl: address) {}` (exactly one address param, empty body). The three
   *  synthesized FunctionIRs are pushed into `functions` (ordinary dispatcher entries with a beaconKind). */
  private synthesizeBeacon(
    cls: ts.ClassDeclaration,
    functions: FunctionIR[],
    stateVarCount: number,
    hasReceive: boolean,
    hasFallback: boolean,
  ): void {
    // A beacon owns fixed storage slots 0 (owner) and 1 (implementation); user state would collide.
    if (stateVarCount > 0)
      this.diags.error(
        cls,
        'JETH406',
        'a @beacon class may not declare @state/@constant/@immutable (the owner and implementation live in reserved storage slots 0 and 1; the whole UpgradeableBeacon surface is synthesized)',
      );
    if (hasReceive || hasFallback)
      this.diags.error(
        cls,
        'JETH406',
        'a @beacon class may not declare a @receive/@fallback entry (the UpgradeableBeacon surface is fully synthesized)',
      );
    if (heritageBases(cls).length > 0)
      this.diags.error(
        cls,
        'JETH406',
        'a @beacon class may not extend another contract (the UpgradeableBeacon surface is fully synthesized)',
      );
    // The user MUST declare `constructor(impl: address) {}` - exactly one address param, an EMPTY body
    // (JETH synthesizes the owner/impl init in creation). The single param defines the appended ctor arg.
    const ctorNode = this.ctorChain[0]?.node;
    if (!ctorNode) {
      this.diags.error(
        cls,
        'JETH407',
        "a @beacon class must declare 'constructor(impl: address) {}' (the implementation the beacon initially points at; the body must be empty)",
      );
    } else {
      const ps = ctorNode.parameters;
      const ok =
        ps.length === 1 &&
        ts.isIdentifier(ps[0]!.name) &&
        resolveType(ps[0]!.type, this.diags, this.structsByName)?.kind === 'address';
      if (!ok)
        this.diags.error(ctorNode, 'JETH407', "a @beacon constructor must take exactly one parameter 'impl: address'");
      const bodyStmts = ctorNode.body?.statements ?? ts.factory.createNodeArray();
      if (bodyStmts.length > 0)
        this.diags.error(
          ctorNode,
          'JETH407',
          'a @beacon constructor body must be empty (the owner/implementation initialization is synthesized)',
        );
      if (ctorDecoratorNames(ctorNode).includes('payable'))
        this.diags.error(
          ctorNode,
          'JETH407',
          'a @beacon constructor may not be @payable (the UpgradeableBeacon constructor is non-payable, matching OZ)',
        );
    }
    // Reject a user-declared upgradeTo/implementation/owner (clash with the synthesized entries). The
    // generic JETH044 would also catch it, but this is more precise.
    for (const name of ['upgradeTo', 'implementation', 'owner']) {
      if ((this.candidatesByName.get(name) ?? []).length > 0) {
        this.diags.error(
          cls,
          'JETH408',
          `a @beacon class may not declare '${name}' (the ${name}(...) entry is synthesized by @beacon)`,
        );
        return;
      }
    }
    // Push the three @external entries (hand-written bodies emitted in yul via beaconKind).
    const upgradeSig = functionSignature('upgradeTo', [ADDRESS]);
    functions.push({
      name: 'upgradeTo',
      key: 'upgradeTo',
      visibility: 'external',
      mutability: 'nonpayable',
      params: [{ name: 'newImplementation', type: ADDRESS }],
      returnType: VOID,
      signature: upgradeSig,
      selector: functionSelector(upgradeSig),
      body: [],
      beaconKind: 'upgradeTo',
    });
    const implSig = functionSignature('implementation', []);
    functions.push({
      name: 'implementation',
      key: 'implementation',
      visibility: 'external',
      mutability: 'view',
      params: [],
      returnType: ADDRESS,
      signature: implSig,
      selector: functionSelector(implSig),
      body: [],
      beaconKind: 'implementation',
    });
    const ownerSig = functionSignature('owner', []);
    functions.push({
      name: 'owner',
      key: 'owner',
      visibility: 'external',
      mutability: 'view',
      params: [],
      returnType: ADDRESS,
      signature: ownerSig,
      selector: functionSelector(ownerSig),
      body: [],
      beaconKind: 'owner',
    });
  }

  /** Phase B: build the LibraryIR list for every referenced external (delegatecall) library. For each
   *  such L, `external` = L's @external FunctionIRs; `internal` = the library functions reachable from
   *  one of those external entries through internal-call edges (excluding the external entries). Each
   *  internal one is forced `internallyCalled` so the library object emits its userfn_. Returns [] when
   *  no external library was referenced. */
  private partitionExternalLibraries(functions: FunctionIR[], callGraph: Map<string, Set<string>>): LibraryIR[] {
    if (this.referencedExternalLibraries.size === 0) return [];
    const byKey = new Map<string, FunctionIR>();
    for (const f of functions) byKey.set(f.key, f);
    // key -> the owning library name (a library FunctionIR).
    const libOf = new Map<string, string>();
    for (const [lib, fns] of this.libraryByName) {
      for (const rf of fns) libOf.set(this.fkey(rf), lib);
    }
    const out: LibraryIR[] = [];
    for (const lib of [...this.referencedExternalLibraries].sort()) {
      const externalKeys = (this.libraryByName.get(lib) ?? [])
        .filter((rf) => rf.libraryExternal)
        .map((rf) => this.fkey(rf));
      // BFS over internal-call edges from the external entries; collect the reachable LIBRARY functions.
      const reachable = new Set<string>();
      const stack = [...externalKeys];
      while (stack.length) {
        const k = stack.pop()!;
        for (const c of callGraph.get(k) ?? []) {
          if (reachable.has(c)) continue;
          reachable.add(c);
          stack.push(c);
        }
      }
      const external: FunctionIR[] = [];
      for (const k of externalKeys) {
        const f = byKey.get(k);
        if (f) external.push(f);
      }
      const internal: FunctionIR[] = [];
      for (const k of reachable) {
        if (externalKeys.includes(k)) continue;
        const f = byKey.get(k);
        if (!f) continue;
        // Only LIBRARY functions become object-local userfn_s (a library never calls a contract fn).
        if (!libOf.has(k)) continue;
        const clone: FunctionIR = { ...f, internallyCalled: true };
        internal.push(clone);
      }
      out.push({ name: lib, external, internal });
    }
    return out;
  }

  /** Phase B: the contract object's retained function list once external libraries are split out. Drops
   *  every @external library function (a delegatecall entry, not a contract entry) and every library
   *  function NOT reachable from a CONTRACT entry (it lives only in a library object). A library internal
   *  function the contract inlines stays. */
  private contractRetainedFunctions(functions: FunctionIR[], callGraph: Map<string, Set<string>>): FunctionIR[] {
    // Keys of @external library functions (delegatecall entries) and of ALL library functions (by source
    // name `L.f`). A non-library function is always contract-retained.
    const libExternalKeys = new Set<string>();
    const libFnKeys = new Set<string>();
    for (const fns of this.libraryByName.values())
      for (const rf of fns) {
        libFnKeys.add(this.fkey(rf));
        if (rf.libraryExternal) libExternalKeys.add(this.fkey(rf));
      }
    // Contract-reachable: BFS from every NON-library function (the contract's own functions + getters),
    // following internal-call edges, so a library internal fn the contract inlines stays.
    const contractReachable = new Set<string>();
    const stack: string[] = [];
    for (const f of functions) {
      if (!libFnKeys.has(f.key)) {
        contractReachable.add(f.key);
        stack.push(f.key);
      }
    }
    while (stack.length) {
      const k = stack.pop()!;
      for (const c of callGraph.get(k) ?? []) {
        if (contractReachable.has(c)) continue;
        contractReachable.add(c);
        stack.push(c);
      }
    }
    return functions.filter((f) => {
      if (libExternalKeys.has(f.key)) return false; // a delegatecall entry, never in the contract
      if (libFnKeys.has(f.key) && !contractReachable.has(f.key)) return false; // library-only function
      return true;
    });
  }

  // ---- inheritance: override resolution + super -----------------------------

  // The C3 linearization (most-derived first), set in resolveOverrides for super resolution.
  private linOrder: string[] = [];
  // Non-winning base function versions kept ONLY as `super` targets, keyed `<Contract>__<sig>`.
  // Checked separately and emitted as forced-internal userfn_<key>. Keyed by the same per-contract
  // super key set in resolveOverrides.
  private superTargets: RawFunction[] = [];
  // super dispatch table: for a signature, the ORDERED chain of (implemented) versions in the
  // linearization that define it (most-derived first). super.f() inside `Cx` resolves to the FIRST
  // version after Cx in this chain. The head's key is the winner's bare/overload key (resolved after
  // overload keying via winnerRef); non-head entries carry per-contract super keys. `rf` is the
  // version's RawFunction (for arg type-checking when super resolves to it).
  private overrideChains = new Map<
    string,
    { contract: string; key: string; winnerRef?: RawFunction; rf: RawFunction }[]
  >();

  /** A signature key for grouping override sets: source name + canonical parameter types (a
   *  differing RETURN type does not change identity; solc requires it to MATCH on an override). */
  private sigKey(rf: RawFunction): string {
    return `${rf.name}(${rf.params.map((p) => canonicalName(p.type)).join(',')})`;
  }

  /** Resolve the override sets across the linearization. Returns the WINNERS (most-derived definition
   *  per signature) to feed the normal register/check/dispatch pipeline; non-winning base versions are
   *  stashed in this.superTargets (reachable only via super). Enforces every virtual/override/list/
   *  return-type/mutability/visibility rule the spec verified against solc. */
  private resolveOverrides(lin: ts.ClassDeclaration[], collected: RawFunction[]): RawFunction[] {
    this.linOrder = lin.map((c) => c.name?.text ?? '<anon>');
    const linIndex = new Map(this.linOrder.map((n, i) => [n, i]));
    const deployedName = this.linOrder[0]!;
    const deployedAbstract = this.isAbstractClass(lin[0]!);

    // Group by signature; within a group order by linearization (most-derived first). collected is
    // already in linearization order (we iterated lin most-derived first), so a stable sort by the
    // defining contract's linearization index preserves that.
    const groups = new Map<string, RawFunction[]>();
    for (const rf of collected) {
      const k = this.sigKey(rf);
      const g = groups.get(k);
      if (g) g.push(rf);
      else groups.set(k, [rf]);
    }
    for (const g of groups.values()) {
      g.sort((a, b) => (linIndex.get(a.definingContract!) ?? 0) - (linIndex.get(b.definingContract!) ?? 0));
    }

    const winners: RawFunction[] = [];
    const mutRank: Record<Mutability, number> = { payable: 3, nonpayable: 2, view: 1, pure: 0 };

    // Transitive bases of each contract in the linearization (for the diamond override-list check):
    // a function that overrides versions from 2+ SIBLING base contracts (neither a base of the other)
    // must name them all in @override(B, K), matching solc.
    const byName = new Map(lin.map((c) => [c.name?.text ?? '<anon>', c]));
    const basesOf = new Map<string, Set<string>>();
    const computeBases = (cn: string): Set<string> => {
      const cached = basesOf.get(cn);
      if (cached) return cached;
      const out = new Set<string>();
      basesOf.set(cn, out); // set first to tolerate a (rejected-elsewhere) cycle
      const cls = byName.get(cn);
      if (cls)
        for (const b of heritageBases(cls)) {
          out.add(b.name);
          for (const bb of computeBases(b.name)) out.add(bb);
        }
      return out;
    };
    for (const cn of this.linOrder) computeBases(cn);

    for (const [sk, versions] of groups) {
      // If every version of this signature is declared in the SAME contract, this is NOT an override
      // relationship - it is either a single function or a same-contract duplicate (handled by the
      // overload resolver / JETH044). Pass them all through unchanged (pre-inheritance behaviour). An
      // inherited (or own) bodyless @virtual that the non-@abstract deployed contract never implements
      // is still unimplemented -> JETH380 (the check below is skipped with the rest of the loop).
      if (new Set(versions.map((v) => v.definingContract)).size <= 1) {
        const w = versions[0]!;
        if (w.bodyless && !deployedAbstract) {
          this.diags.error(
            w.node,
            'JETH380',
            `contract '${deployedName}' is not @abstract but does not implement inherited @virtual function '${w.name}' (provide an @override implementation or mark the contract @abstract)`,
          );
        }
        winners.push(...versions);
        continue;
      }
      const winner = versions[0]!;
      const isSingle = versions.length === 1;

      // virtual/override correctness across the chain. Order in `versions` is most-derived -> base.
      for (let i = 0; i < versions.length; i++) {
        const v = versions[i]!;
        const baseBelow = versions[i + 1]; // the immediately-more-base definition this one overrides
        const isMostDerived = i === 0;

        // @override is REQUIRED on every redefinition (including the first concrete impl of a bodyless
        // @virtual). A definition with NO more-base version must NOT carry @override.
        if (baseBelow) {
          if (!v.isOverride) {
            this.diags.error(
              v.node,
              'JETH374',
              `function '${v.name}' in '${v.definingContract}' overrides a base function but is missing @override`,
            );
          }
          // the overridden base version must be @virtual (a non-virtual base cannot be overridden).
          if (!baseBelow.isVirtual) {
            this.diags.error(
              v.node,
              'JETH375',
              `function '${v.name}' overrides '${baseBelow.definingContract}.${baseBelow.name}', which is not @virtual`,
            );
          }
          // an INTERMEDIATE override that is itself further overridden must ALSO be @virtual (a
          // 3-level chain with a non-virtual middle is rejected by solc).
          if (!isMostDerived && !v.isVirtual) {
            this.diags.error(
              v.node,
              'JETH376',
              `function '${v.name}' in '${v.definingContract}' is overridden by a more-derived contract but is not @virtual`,
            );
          }
          // return type must be identical across the override pair.
          if (!this.overrideReturnsEqual(v, baseBelow)) {
            this.diags.error(
              v.node,
              'JETH377',
              `override of '${v.name}' must keep the exact return type of '${baseBelow.definingContract}.${baseBelow.name}'`,
            );
          }
          // mutability one-way ladder (payable > nonpayable > view > pure): the override may only be
          // EQUAL or MORE restrictive; payable may be overridden only by payable.
          const dr = mutRank[v.mutability];
          const br = mutRank[baseBelow.mutability];
          const crossesPayable = (v.mutability === 'payable') !== (baseBelow.mutability === 'payable');
          if (dr > br || crossesPayable) {
            this.diags.error(
              v.node,
              'JETH378',
              `override of '${v.name}' cannot loosen mutability (@${baseBelow.mutability} -> @${v.mutability}); an override may only keep or tighten it, and payable crosses are forbidden`,
            );
          }
          // visibility: external may be overridden by external (or, in solc, by public); JETH maps
          // public->external. An external/internal mismatch across the pair is rejected.
          if (v.visibility !== baseBelow.visibility) {
            this.diags.error(
              v.node,
              'JETH379',
              `override of '${v.name}' changes visibility (@${baseBelow.visibility} -> @${v.visibility}); the override must keep the base visibility`,
            );
          }
        } else {
          // a base-most definition carrying @override with nothing to override is an error.
          if (v.isOverride) {
            this.diags.error(
              v.node,
              'JETH374',
              `function '${v.name}' in '${v.definingContract}' has @override but overrides no base function`,
            );
          }
        }
      }

      // DIAMOND override-list completeness (solc: "Function needs to specify overridden contracts B
      // and C"). The branch heads = overridden contracts that are NOT a base of another overridden
      // contract (the maximal sibling versions). With 2+ heads, the winner must name them all in
      // @override(B, K); a bare @override or an incomplete list is rejected.
      const overridden = [...new Set(versions.slice(1).map((v) => v.definingContract!))];
      const heads = overridden.filter((x) => !overridden.some((y) => y !== x && basesOf.get(y)?.has(x)));
      if (heads.length >= 2) {
        const list = winner.overrideList ?? [];
        const missing = heads.filter((h) => !list.includes(h));
        if (missing.length > 0) {
          this.diags.error(
            winner.node,
            'JETH381',
            `function '${winner.name}' overrides more than one base contract; it must specify @override(${heads.join(', ')})`,
          );
        }
      }

      // A bodyless (unimplemented @virtual) definition that is NEVER overridden by a concrete impl,
      // in a NON-abstract deployed contract, is unimplemented -> reject. (If the winner itself is
      // bodyless and the deployed contract is concrete, it stays abstract.)
      if (winner.bodyless && !deployedAbstract) {
        this.diags.error(
          winner.node,
          'JETH380',
          `contract '${deployedName}' is not @abstract but does not implement inherited @virtual function '${winner.name}' (provide an @override implementation or mark the contract @abstract)`,
        );
      }

      // Build the super-resolution chain for this signature: [{contract,key}] most-derived first,
      // skipping bodyless versions (they are not callable super targets). The winner uses its bare
      // key (assigned later by the normal overload-keying); non-winners get a per-contract key now.
      const chain: { contract: string; key: string; winnerRef?: RawFunction; rf: RawFunction }[] = [];
      for (let i = 0; i < versions.length; i++) {
        const v = versions[i]!;
        if (i === 0) {
          // winner: register normally; its key is the bare name (or name__ovN). Mark definingContract.
          // winnerRef lets analyzeContract backfill the real key after overload keying. A bodyless
          // winner (a still-abstract method on an @abstract deployed contract) is not super-callable.
          chain.push({ contract: v.definingContract!, key: '<winner>', winnerRef: v.bodyless ? undefined : v, rf: v });
          winners.push(v);
        } else {
          // a super target: give it a deterministic per-contract key and stash it. It is forced
          // internal (emitted as userfn_<key>), reachable only via super. A bodyless base version is
          // NOT emitted (no body) but is skipped from the chain so super never targets it.
          if (!v.bodyless) {
            v.key = `${v.definingContract}__super__${this.sanitizeSig(sk)}`;
            v.visibility = 'internal'; // a super target is an internal call target, never in the ABI
            this.superTargets.push(v);
            chain.push({ contract: v.definingContract!, key: v.key, rf: v });
          }
        }
      }
      this.overrideChains.set(sk, chain);
      void isSingle;
    }
    return winners;
  }

  /** Stable identifier fragment for a signature (super-target key). Keep it readable + collision-free
   *  by hashing the parens/commas away to underscores; the contract prefix already disambiguates. */
  private sanitizeSig(sk: string): string {
    return sk.replace(/[^A-Za-z0-9_]+/g, '_').replace(/_+$/g, '');
  }

  /** Whether two override versions have an identical return shape (single or multi-value). */
  private overrideReturnsEqual(a: RawFunction, b: RawFunction): boolean {
    if (a.returnTypes || b.returnTypes) {
      const ra = a.returnTypes ?? [];
      const rb = b.returnTypes ?? [];
      if (ra.length !== rb.length) return false;
      return ra.every((t, i) => typesEqual(t, rb[i]!));
    }
    return typesEqual(a.returnType, b.returnType);
  }

  /** Synthesize the solc auto-getter for a @public state variable, or null when its shape is not
   *  yet supported. solc parameterizes the getter: each mapping level contributes a key param, each
   *  array level a uint256 index param. A value/bytes/string leaf returns directly; a STRUCT leaf is
   *  flattened into a value/bytes/string-field tuple (omitting array+mapping members, recursively
   *  inlining all-static nested structs). Byte-identical to solc, incl. empty-revert on OOB. */
  private synthPublicGetter(v: StateVar): FunctionIR | null {
    const params: Param[] = [];
    const keys: Expr[] = []; // mapping keys, for the specialized mapGet/mapArray value encoders
    const keyTypes: JethType[] = [];
    const indices: Expr[] = []; // array index params
    const arrTypes: Extract<JethType, { kind: 'array' }>[] = [];
    const prefix: AccessStep[] = []; // generic navigation (mapKey + index) for STRUCT leaves
    let t: JethType = v.type;
    let argi = 0;
    while (t.kind === 'mapping') {
      const nm = `arg${argi++}`;
      params.push({ name: nm, type: t.key });
      // a bytes/string key is a dynamic (calldata) value; a value-type key is a register local.
      const key: Expr = isBytesLike(t.key)
        ? { kind: 'dynParamRead', type: t.key, name: nm }
        : { kind: 'localRead', type: t.key, name: nm };
      keys.push(key);
      keyTypes.push(t.key);
      prefix.push({ kind: 'mapKey', key, valueType: t.value });
      t = t.value;
    }
    while (t.kind === 'array') {
      const nm = `arg${argi++}`;
      params.push({ name: nm, type: U256 });
      const idx: Expr = { kind: 'localRead', type: U256, name: nm };
      indices.push(idx);
      arrTypes.push(t);
      prefix.push(this.getterArrayStep(t, idx));
      t = t.element;
      if (t.kind === 'mapping') return null; // array-of-mapping (not valid Solidity anyway)
    }
    const sig = functionSignature(
      v.name,
      params.map((p) => p.type),
    );
    const base = {
      name: v.name,
      key: `getter$${v.name}`,
      visibility: 'external' as const,
      mutability: 'view' as const,
      params,
      signature: sig,
      selector: functionSelector(sig),
    };

    // STRUCT leaf: flatten to a value/bytes/string-field tuple, reached via the navigation prefix;
    // array-element OOB reverts EMPTY (solc parity). The TOP struct omits ALL array + mapping members;
    // a kept nested struct is a FULL sub-tuple (its fixed arrays ARE included).
    if (t.kind === 'struct') {
      const flat = this.flattenGetterStruct(t, v.slot, prefix, true);
      if (!flat) return null;
      return {
        ...base,
        returnType: VOID,
        returnTypes: flat.types,
        body: [{ kind: 'returnTuple', values: flat.values, types: flat.types }],
      };
    }

    // Value / bytes / string leaf.
    if (!(isStaticValueType(t) || isBytesLike(t))) return null;
    let value: Expr | null = null;
    if (indices.length === 0 && keys.length === 0) {
      value = isStaticValueType(t)
        ? { kind: 'stateRead', type: t, slot: v.slot, offset: v.offset, varName: v.name }
        : { kind: 'dynStateRead', type: t, slot: v.slot };
    } else if (indices.length === 0) {
      value = isBytesLike(t)
        ? { kind: 'mapDynValue', type: t, baseSlot: v.slot, keys, keyTypes }
        : { kind: 'mapGet', type: t, baseSlot: v.slot, keys, keyTypes };
    } else if (indices.length === 1 && (keys.length === 0 || arrTypes[0]!.length === undefined)) {
      // single dynamic/fixed array (no mapping) or mapping->DYNAMIC array: the proven ArrayExpr path.
      const arrType = arrTypes[0]!;
      const arr: ArrayExpr =
        keys.length > 0
          ? { base: { kind: 'mapArray', baseSlot: v.slot, keys, keyTypes }, elem: t }
          : arrType.length !== undefined
            ? { base: { kind: 'fixedArray', baseSlot: v.slot, length: arrType.length }, elem: t }
            : { base: { kind: 'stateArray', slot: v.slot }, elem: t };
      value = isBytesLike(t)
        ? { kind: 'strArrayElem', type: t, arr, index: indices[0]!, oobEmpty: true }
        : { kind: 'arrayGet', type: t, arr, index: indices[0]!, oobEmpty: true };
    }
    if (!value) {
      // Generic fallback for the remaining shapes (nested arrays T[][], string[][], mapping(K=>Arr<T,N>),
      // mapping(K=>Arr<string,N>), ...): read the leaf at the resolved place (the packing-aware prefix).
      // A bytes/string leaf is a storage dynamic value at the folded slot (dynPlaceRead).
      const path: AccessPath = { baseSlot: v.slot, steps: prefix, oobEmpty: true };
      value = isBytesLike(t) ? { kind: 'dynPlaceRead', type: t, path } : { kind: 'placeRead', type: t, path };
    }
    return { ...base, returnType: t, body: [{ kind: 'return', value }] };
  }

  /** Synthesize the view getter for an `@external @immutable` field (solc's `public immutable`
   *  auto-getter). `name() view returns (T)` returns the immutable via a loadimmutable read (a code
   *  read, NOT a storage read - it consumes no slot), byte-identical to solc's generated getter:
   *  selector = keccak(name+"()")[:4], returndata = the immutable value ABI-encoded. An immutable is
   *  always a value type (collectImmutable gates it via isStaticValueType), so no parameters / no
   *  aggregate encoding is needed. VIEW (not pure): a loadimmutable "reads the environment". */
  private synthImmutableGetter(im: { name: string; type: JethType }): FunctionIR {
    const sig = functionSignature(im.name, []);
    return {
      name: im.name,
      key: `immGetter$${im.name}`,
      visibility: 'external',
      mutability: 'view',
      params: [],
      signature: sig,
      selector: functionSelector(sig),
      returnType: im.type,
      body: [{ kind: 'return', value: { kind: 'immutableRead', type: im.type, name: im.name } }],
    };
  }

  /** Build the AccessStep for one array level of a @public getter, mirroring the element-access codec
   *  (packed iff a non-aggregate element smaller than a slot). Used to navigate to a struct/value leaf. */
  private getterArrayStep(arr: Extract<JethType, { kind: 'array' }>, idx: Expr): AccessStep {
    const elem = arr.element;
    const packed = elem.kind !== 'struct' && elem.kind !== 'array' && storageByteSize(elem) < 32;
    if (arr.length !== undefined) {
      return packed
        ? {
            kind: 'packedIndex',
            index: idx,
            perSlot: Math.floor(32 / storageByteSize(elem)),
            size: storageByteSize(elem),
            length: arr.length,
            elemType: elem,
          }
        : { kind: 'index', index: idx, strideSlots: storageSlotCount(elem), length: arr.length, elemType: elem };
    }
    return packed
      ? {
          kind: 'packedDynIndex',
          index: idx,
          perSlot: Math.floor(32 / storageByteSize(elem)),
          size: storageByteSize(elem),
          elemType: elem,
        }
      : { kind: 'dynIndex', index: idx, strideSlots: storageSlotCount(elem), elemType: elem };
  }

  /** Flatten a @public struct getter's return tuple: each value/bytes/string field (in declaration
   *  order, OMITTING array+mapping members) becomes a tuple component read via `prefix`+field steps
   *  from `baseSlot`; an all-static nested struct is recursively inlined (byte-identical to solc,
   *  whose static nested tuple encodes inline). Returns null when a nested struct is non-static (a
   *  dynamic nested tuple would not match a flattened encoding) or the result tuple is empty. */
  private flattenGetterStruct(
    st: Extract<JethType, { kind: 'struct' }>,
    baseSlot: bigint,
    prefix: AccessStep[],
    top: boolean,
  ): { types: JethType[]; values: Expr[] } | null {
    const types: JethType[] = [];
    const values: Expr[] = [];
    for (const f of st.fields) {
      if (f.type.kind === 'mapping') continue; // solc omits mappings at any level
      // The directly-returned (top) struct OMITS arrays (fixed AND dynamic); a nested struct is a full
      // sub-tuple whose FIXED arrays are included (a nested DYNAMIC array isn't flattenable -> defer).
      if (top && f.type.kind === 'array') continue;
      if (!top && f.type.kind === 'array' && f.type.length === undefined) return null;
      const steps: AccessStep[] = [
        ...prefix,
        { kind: 'field', fieldSlot: f.slot, fieldOffset: f.offset, fieldType: f.type },
      ];
      const r = this.flattenGetterLeaf(f.type, baseSlot, steps);
      if (!r) return null;
      types.push(...r.types);
      values.push(...r.values);
    }
    return types.length ? { types, values } : null;
  }

  /** Flatten one struct-getter leaf reached by `steps`: a value/`bytes`/`string` field is one tuple
   *  component; an all-static nested struct recurses; a FIXED-size array is inlined as its N elements
   *  (solc INCLUDES fixed arrays, omitting only dynamic arrays/mappings). Returns null for shapes whose
   *  flattened encoding would not match solc's nested tuple (a dynamic nested struct, or a fixed array
   *  of bytes/string/array/dynamic-struct). */
  private flattenGetterLeaf(
    type: JethType,
    baseSlot: bigint,
    steps: AccessStep[],
  ): { types: JethType[]; values: Expr[] } | null {
    const path: AccessPath = { baseSlot, steps, oobEmpty: true };
    if (isStaticValueType(type)) return { types: [type], values: [{ kind: 'placeRead', type, path }] };
    if (isBytesLike(type)) return { types: [type], values: [{ kind: 'dynPlaceRead', type, path }] };
    if (type.kind === 'struct') {
      if (isStaticType(type)) return this.flattenGetterStruct(type, baseSlot, steps, false); // static: flatten inline (byte-identical)
      // A DYNAMIC nested struct is a head/tail ABI sub-tuple, NOT a flattened inline run. Emit it as ONE
      // whole storage-struct component: a struct-typed placeRead, which the multi-return codec resolves
      // to its slot via lowerPlace (a CONSTANT slot for a direct var, or a RUNTIME keccak slot when the
      // struct is reached through a mapping/array) and encodes via the recursive storage encoder.
      return { types: [type], values: [{ kind: 'placeRead', type, path }] };
    }
    if (type.kind === 'array' && type.length !== undefined) {
      const el = type.element;
      if (!(isStaticValueType(el) || (el.kind === 'struct' && isStaticType(el)))) return null; // fixed array of bytes/string/array/dyn-struct: defer
      const types: JethType[] = [];
      const values: Expr[] = [];
      for (let j = 0; j < type.length; j++) {
        const r = this.flattenGetterLeaf(el, baseSlot, [
          ...steps,
          this.getterArrayStep(type, { kind: 'literalInt', type: U256, value: BigInt(j) }),
        ]);
        if (!r) return null;
        types.push(...r.types);
        values.push(...r.values);
      }
      return types.length ? { types, values } : null;
    }
    return null;
  }

  /** Phase 5: validate a constructor declaration + type-check its body into a ConstructorIR.
   *  Increment 1 supports value-type params (decoded from the appended init-code args in
   *  emitCreation) and a body that writes/reads @state + reads msg.sender/msg.value(@payable)/
   *  address(this). Aggregate params and ctor->internal-calls are cleanly gated. */
  /** Type-check the @immutable inline initializers (`@immutable a = expr`) into staged-assignment
   *  statements that run at the START of the constructor, in declaration order. Checked in a FRESH
   *  scope (no constructor params - a field initializer cannot reference them, matching solc) with the
   *  in-constructor flag set so the immutable write is permitted. */
  private immutableInitStmts(): Stmt[] {
    const stmts: Stmt[] = [];
    const savedScopes = this.scopes;
    const savedInCtor = this.currentInConstructor;
    const savedMut = this.currentMutability;
    this.scopes = [new Map()];
    this.pushScope();
    this.currentInConstructor = true;
    this.currentMutability = 'nonpayable'; // a field initializer has no payable context (msg.value -> JETH162)
    this.currentExternallyReachable = true; // strict: a field initializer cannot read msg.value (nonpayable)
    for (const name of this.immutableOrder) {
      const im = this.immutablesByName.get(name)!;
      if (!im.init) continue;
      const v = this.checkExpr(im.init, im.type);
      if (!v) continue;
      const coerced = this.coerce(v, im.type, im.init);
      stmts.push({ kind: 'assign', target: { kind: 'immutableStaged', type: im.type, name }, value: coerced });
    }
    this.popScope();
    this.scopes = savedScopes;
    this.currentInConstructor = savedInCtor;
    this.currentMutability = savedMut;
    return stmts;
  }

  private checkConstructor(ctorNode: ts.ConstructorDeclaration): ConstructorIR | undefined {
    // Decorators: @payable makes the ctor payable (default non-payable; solc rejects a view/pure ctor
    // -> JETH301). A user @modifier MAY decorate a constructor (the canonical base-init guard, e.g.
    // `constructor() onlyValid {}`); it is inlined around the body like a function modifier. ctors
    // report ts.canHaveDecorators === false, so read the decorators via ts.getDecorators directly.
    let payable = false;
    const ctorMods: { name: string; argNodes: ts.Expression[]; site: ts.Node }[] = [];
    const CTOR_BAD_DECORATORS = new Set([
      'view',
      'pure',
      'read',
      'nonReentrant',
      'external',
      'public',
      'internal',
      'private',
      'hidden',
    ]);
    for (const dec of ts.getDecorators(ctorNode as unknown as ts.HasDecorators) ?? []) {
      const e = dec.expression;
      let nm: string | undefined;
      let args: ts.Expression[] = [];
      if (ts.isIdentifier(e)) nm = e.text;
      else if (ts.isCallExpression(e) && ts.isIdentifier(e.expression)) {
        nm = e.expression.text;
        args = [...e.arguments];
      }
      if (!nm) continue;
      if (nm === 'payable') payable = true;
      else if (CTOR_BAD_DECORATORS.has(nm))
        this.diags.error(
          ctorNode,
          'JETH301',
          `a constructor cannot be @${nm} (a constructor is payable or non-payable only)`,
        );
      else ctorMods.push({ name: nm, argNodes: args, site: dec }); // a @modifier application, inlined below
    }
    if (ctorNode.type) this.diags.error(ctorNode.type, 'JETH301', 'a constructor cannot declare a return type');
    if (ctorNode.typeParameters && ctorNode.typeParameters.length > 0) {
      this.diags.error(ctorNode, 'JETH301', 'a constructor cannot be generic');
    }

    // Params: value types only in increment 1 (decoded from memory via mload + validateInput).
    const params: Param[] = [];
    for (const p of ctorNode.parameters) {
      if (!ts.isIdentifier(p.name)) {
        this.diags.error(p, 'JETH053', 'parameter name must be a plain identifier');
        continue;
      }
      const t = resolveType(p.type, this.diags, this.structsByName);
      if (!t) continue;
      if (p.initializer)
        this.diags.error(p, 'JETH304', `a constructor parameter ('${p.name.text}') cannot have a default value`);
      if (this.typeHasMapping(t)) {
        this.diags.error(
          p,
          'JETH247',
          `constructor parameter '${p.name.text}' of type ${displayName(t)} contains a mapping and cannot be passed (mappings are storage-only)`,
        );
        continue;
      }
      if (!this.ctorParamSupported(t)) {
        this.diags.error(
          p,
          'JETH302',
          `constructor parameter '${p.name.text}' of type ${displayName(t)} is not supported yet`,
        );
        continue;
      }
      params.push({ name: p.name.text, type: t });
    }

    // Type-check the body with a fresh function-like context (modeled on checkFunction). Setting
    // currentMutability is sufficient to enforce the payable rule: a msg.value read flows through
    // checkGlobal's cat==='value' branch (JETH162) when currentMutability !== 'payable'.
    this.scopes = [];
    this.loopDepth = 0;
    this.pushScope();
    this.currentMutability = payable ? 'payable' : 'nonpayable';
    this.currentExternallyReachable = true; // a constructor is externally reachable: msg.value needs a payable ctor
    this.currentWritesState = false;
    this.currentReadsState = false;
    this.currentReadsEnv = false;
    this.currentReturnTypes = undefined;
    this.currentCallees = new Set();
    this.memArrayLocals.clear();
    this.memAggregateLocals.clear();
    this.memDynLocals.clear();
    this.memDynStructLocals.clear();
    for (const p of params) {
      if (this.inCurrentScope(p.name)) this.diags.error(ctorNode, 'JETH056', `duplicate parameter name '${p.name}'`);
      this.declareLocal(p.name, p.type);
      // An aggregate/dynamic ctor param is decoded into MEMORY (from the appended creation args) and
      // behaves like an @internal function's memory-reference param, so register it in the same maps
      // (a body read of p[i]/p.x/p.length/return p then resolves to a memory place, not calldata).
      this.registerAggregateCtorParam(p.name, p.type);
    }
    // currentInConstructor routes a `this.<imm>` read to the staged shadow (the value assigned so
    // far) instead of a runtime loadimmutable, and permits an @immutable write (only here). It spans
    // the body AND any constructor-modifier inlining (so a ctor modifier reading an immutable also
    // sees the staged value).
    this.currentInConstructor = true;
    // @immutable inline initializers run first, before the explicit constructor body (solc parity).
    const rawBody: Stmt[] = this.immutableInitStmts();
    if (ctorNode.body) {
      this.pushScope();
      // VOID return type: a bare `return;` is allowed (exits early); `return expr;` is rejected
      // by coerce-to-void, matching solc ('Return arguments not allowed' for a constructor).
      for (const s of ctorNode.body.statements) this.checkStatement(s, VOID, rawBody);
      this.popScope();
    }
    // Inline applied @modifiers around the constructor body (param scope active for arg
    // materialization; leftmost decorator outermost). A ctor modifier reading msg.value still flows
    // through the payable rule, and one calling an internal function is caught by the JETH303 gate.
    let body = rawBody;
    for (const app of [...ctorMods].reverse()) body = this.inlineModifier(app, body);
    this.currentInConstructor = false;
    this.popScope();

    // A ctor calling an internal/private function: the transitively-reachable callees are duplicated
    // into the CREATION object by emitConstructor (the call graph keys are recorded in this.callGraph),
    // so the ctor body's calls resolve there. JETH303 (the over-rejection) is lifted.

    return { params, payable, body };
  }

  /** Phase 6: type-check a @receive / @fallback special entry's body into a SpecialEntryIR (a constructor-
   *  like, function-scoped context). @receive is ALWAYS payable (no params, no return, no redundant
   *  @payable). @fallback is non-payable by default (opt-in @payable); v1 rejects params and a return type
   *  (the raw-bytes fallback is gated, JETH384). Both reject @view/@pure/@external/etc. */
  private checkSpecialEntry(member: ts.MethodDeclaration, kind: 'receive' | 'fallback'): SpecialEntryIR | undefined {
    const decs = decoratorNames(member);
    let payable = kind === 'receive'; // @receive is always payable
    const BAD = [
      'view',
      'pure',
      'read',
      'hidden',
      'nonReentrant',
      'external',
      'public',
      'internal',
      'private',
      'virtual',
      'override',
      'modifier',
      'error',
      'event',
    ];
    for (const d of decs) {
      if (d === kind) continue;
      if (d === 'payable') {
        if (kind === 'receive') {
          this.diags.error(member, 'JETH385', '@receive is always payable; drop the redundant @payable');
        } else {
          payable = true;
        }
      } else if (BAD.includes(d)) {
        this.diags.error(
          member,
          'JETH386',
          `a @${kind} entry cannot be @${d} (a special entry is payable or non-payable only)`,
        );
      } else {
        // an applied @modifier on a special entry is not supported in v1.
        this.diags.error(member, 'JETH386', `a @${kind} entry cannot carry a @modifier in v1`);
      }
    }
    if (member.parameters.length > 0) {
      this.diags.error(
        member,
        'JETH384',
        `a @${kind} entry cannot declare parameters in v1 (the raw-bytes @fallback(d: bytes): bytes form is not yet supported)`,
      );
    }
    if (member.type && member.type.kind !== ts.SyntaxKind.VoidKeyword) {
      this.diags.error(
        member,
        'JETH384',
        `a @${kind} entry cannot declare a return type in v1 (the raw-bytes @fallback(d: bytes): bytes form is not yet supported)`,
      );
    }

    // Type-check the body in a fresh function-like context (modeled on checkConstructor), terminated as
    // a void body. A @receive/@fallback is externally reachable and may read msg.value/msg.data; msg.value
    // flows through the payable rule via currentMutability.
    this.scopes = [];
    this.loopDepth = 0;
    this.pushScope();
    this.currentMutability = payable ? 'payable' : 'nonpayable';
    this.currentExternallyReachable = true;
    this.currentWritesState = false;
    this.currentReadsState = false;
    this.currentReadsEnv = false;
    this.currentReturnTypes = undefined;
    this.currentCallees = new Set();
    this.memArrayLocals.clear();
    this.memAggregateLocals.clear();
    this.memDynLocals.clear();
    this.memDynStructLocals.clear();
    const body: Stmt[] = [];
    if (member.body) {
      this.pushScope();
      for (const s of member.body.statements) this.checkStatement(s, VOID, body);
      this.popScope();
    }
    this.popScope();
    if (this.currentCallees.size > 0) {
      this.diags.error(
        member,
        'JETH387',
        `calling an internal/private function from a @${kind} entry is not supported yet; inline the logic into the entry body`,
      );
    }
    return { payable, returnsBytes: false, body };
  }

  /** @payable + applied-@modifier decorators on a constructor (shared by mergeConstructors). */
  private ctorDecorators(ctorNode: ts.ConstructorDeclaration): {
    payable: boolean;
    ctorMods: { name: string; argNodes: ts.Expression[]; site: ts.Node }[];
  } {
    let payable = false;
    const ctorMods: { name: string; argNodes: ts.Expression[]; site: ts.Node }[] = [];
    const BAD = new Set([
      'view',
      'pure',
      'read',
      'nonReentrant',
      'external',
      'public',
      'internal',
      'private',
      'hidden',
    ]);
    for (const dec of ts.getDecorators(ctorNode as unknown as ts.HasDecorators) ?? []) {
      const e = dec.expression;
      let nm: string | undefined;
      let args: ts.Expression[] = [];
      if (ts.isIdentifier(e)) nm = e.text;
      else if (ts.isCallExpression(e) && ts.isIdentifier(e.expression)) {
        nm = e.expression.text;
        args = [...e.arguments];
      }
      if (!nm) continue;
      if (nm === 'payable') payable = true;
      else if (BAD.has(nm))
        this.diags.error(
          ctorNode,
          'JETH301',
          `a constructor cannot be @${nm} (a constructor is payable or non-payable only)`,
        );
      else ctorMods.push({ name: nm, argNodes: args, site: dec });
    }
    if (ctorNode.type) this.diags.error(ctorNode.type, 'JETH301', 'a constructor cannot declare a return type');
    return { payable, ctorMods };
  }

  /** Resolve a constructor's value-type parameters (shared by the deployed-ctor signature and base
   *  ctors receiving heritage args). Mirrors the param validation in checkConstructor: value types
   *  only (JETH302), no default (JETH304), no mapping (JETH247). A base ctor's params are bound as
   *  memory localDecls (initialized from the provider's coerced arg exprs), so the same value-type
   *  restriction applies. */
  private ctorParams(ctorNode: ts.ConstructorDeclaration): Param[] {
    const params: Param[] = [];
    for (const p of ctorNode.parameters) {
      if (!ts.isIdentifier(p.name)) {
        this.diags.error(p, 'JETH053', 'parameter name must be a plain identifier');
        continue;
      }
      const t = resolveType(p.type, this.diags, this.structsByName);
      if (!t) continue;
      if (p.initializer)
        this.diags.error(p, 'JETH304', `a constructor parameter ('${p.name.text}') cannot have a default value`);
      if (this.typeHasMapping(t)) {
        this.diags.error(
          p,
          'JETH247',
          `constructor parameter '${p.name.text}' of type ${displayName(t)} contains a mapping and cannot be passed (mappings are storage-only)`,
        );
        continue;
      }
      if (!this.ctorParamSupported(t)) {
        this.diags.error(
          p,
          'JETH302',
          `constructor parameter '${p.name.text}' of type ${displayName(t)} is not supported yet`,
        );
        continue;
      }
      if (params.some((q) => q.name === p.name!.getText()))
        this.diags.error(p, 'JETH056', `duplicate parameter name '${p.name.text}'`);
      params.push({ name: p.name.text, type: t });
    }
    return params;
  }

  /** Build the single merged constructor across the inheritance chain (this.ctorChain is most-derived
   *  first). With no inheritance this is exactly the Phase 5 checkConstructor. With a base chain, each
   *  contract's ctor body runs most-BASE-first (solc's body order), each checked in a fresh scope so a
   *  base body cannot see the derived's params. Base-constructor ARGUMENTS (heritage `extends A(args)`
   *  or a base ctor with parameters) are gated (JETH379) for a focused follow-up; the common no-arg
   *  base constructor (the Ownable pattern) is supported. */
  private mergeConstructors(): ConstructorIR | undefined {
    const chain = this.ctorChain;
    const hasInlineImmInit = this.immutableOrder.some((n) => this.immutablesByName.get(n)!.init !== undefined);
    // No inheritance: exact Phase 5 behaviour (single contract). With no constructor but inline
    // @immutable initializers, synthesize a body that stages them (they run in creation code).
    if (chain.length <= 1) {
      if (chain[0]?.node) return this.checkConstructor(chain[0].node);
      return hasInlineImmInit ? { params: [], payable: false, body: this.immutableInitStmts() } : undefined;
    }
    // no constructor anywhere AND no inline immutable init -> no creation-time work beyond defaults.
    if (!chain.some((c) => c.node) && !hasInlineImmInit) return undefined;
    const deployed = chain[0]!;

    // ---- BASE-CONSTRUCTOR ARGUMENTS (lift JETH379 for the supported shapes) ----
    // Resolve, per chain contract index, its ctor PARAMS (value-types only; same validation as the
    // deployed ctor). Base params are bound as memory localDecls in the nested-block builder below, so
    // they must be value types (isStaticValueType) just like the deployed formals.
    const chainParams: Param[][] = chain.map((c) => (c.node ? this.ctorParams(c.node) : []));

    // A base's args may be given by ANOTHER contract's heritage `extends B(args)`. (Modifier-style base
    // args - a `@B(7)` decorator on the deployed ctor - are NOT supported in this increment: they are
    // ambiguous with a real @modifier application; KEEP JETH379 for them, see the ctorMods check below.)
    // Build basename -> provider (which chain contract supplied the args + the arg expr nodes).
    const baseArgProvider = new Map<string, { providerIdx: number; argNodes: ts.Expression[]; site: ts.Node }>();
    let baseArgsGate = false; // true once we have emitted a JETH379 and must not also try to codegen
    for (let pi = 0; pi < chain.length; pi++) {
      for (const b of chain[pi]!.bases) {
        if (b.args === undefined) continue; // a bare `extends B` (no call-form) supplies no args
        // The base named here must be a chain contract WITH a constructor to receive these args.
        const targetIdx = chain.findIndex((c) => c.contract === b.name);
        if (targetIdx < 0) continue; // not a known base (the linearizer already reported it)
        const prior = baseArgProvider.get(b.name);
        if (prior) {
          // Base args given twice (heritage on two different contracts, e.g. both diamond branches
          // specify a shared base). solc rejects ("Base constructor arguments given twice").
          this.diags.error(
            b.node,
            'JETH379',
            `base contract '${b.name}' is given constructor arguments more than once (each base's constructor arguments may be specified only once across the inheritance chain)`,
          );
          baseArgsGate = true;
          continue;
        }
        baseArgProvider.set(b.name, { providerIdx: pi, argNodes: [...b.args], site: b.node });
      }
    }
    // Modifier-style base args (a `@<BaseName>(...)` decorator on the deployed ctor) are GATED: keep
    // JETH379 cleanly rather than guess. Detect a deployed-ctor decorator whose name is a chain base.
    if (deployed.node) {
      for (const dec of ts.getDecorators(deployed.node as unknown as ts.HasDecorators) ?? []) {
        const e = dec.expression;
        if (ts.isCallExpression(e) && ts.isIdentifier(e.expression)) {
          const nm = e.expression.text;
          if (chain.some((c, i) => i !== 0 && c.contract === nm)) {
            this.diags.error(
              dec,
              'JETH379',
              `modifier-style base-constructor arguments ('constructor() ${nm}(...)') are not supported yet; specify the base's arguments via the heritage clause ('extends ${nm}(...)')`,
            );
            baseArgsGate = true;
          }
        }
      }
    }
    // Required-args check: a base with a parameterized ctor that nobody supplied args for. The deployed
    // is a concrete @contract, so solc requires every base ctor's args be supplied ("specify the
    // arguments... or mark X as abstract"). A zero-param base ctor needs no provider.
    for (let i = 1; i < chain.length; i++) {
      const c = chain[i]!;
      if (chainParams[i]!.length === 0) continue; // no params -> no args needed
      const prov = baseArgProvider.get(c.contract);
      if (!prov) {
        this.diags.error(
          deployed.node ?? deployed.cls,
          'JETH379',
          `base contract '${c.contract}' has a constructor with ${chainParams[i]!.length} parameter(s) but no arguments are specified for it (add them via the heritage clause, e.g. 'extends ${c.contract}(...)')`,
        );
        baseArgsGate = true;
        continue;
      }
      // Arity must match (a base ctor with params given empty `extends B()` is a missing-args reject).
      if (prov.argNodes.length !== chainParams[i]!.length) {
        this.diags.error(
          prov.site,
          'JETH379',
          `base contract '${c.contract}' expects ${chainParams[i]!.length} constructor argument(s) but ${prov.argNodes.length} were given`,
        );
        baseArgsGate = true;
      }
    }
    // Args given to a base whose ctor takes NO params (or which has no ctor) -> reject (solc: "Wrong
    // argument count"). e.g. `extends A(7)` where A's ctor has 0 params, or A has no ctor.
    for (const [name, prov] of baseArgProvider) {
      const idx = chain.findIndex((c) => c.contract === name);
      if (idx >= 0 && prov.argNodes.length > 0 && chainParams[idx]!.length === 0) {
        this.diags.error(
          prov.site,
          'JETH379',
          `base contract '${name}' constructor takes no arguments but ${prov.argNodes.length} were given`,
        );
        baseArgsGate = true;
      }
    }
    // GATE the diamond-same-name-sibling hazard: if two bases that BOTH receive args (so both get
    // their params bound as localDecls in the same enclosing provider block) share a ctor PARAM NAME,
    // codegen's flat per-block name map would collide (the second binding shadows the first, so the
    // first base's body would read the wrong value - a silent miscompile). Only a collision among bases
    // bound IN THE SAME provider block matters; bind blocks are per-provider, so group by provider.
    {
      const byProvider = new Map<number, string[]>(); // providerIdx -> all param names it binds
      for (let i = 1; i < chain.length; i++) {
        const prov = baseArgProvider.get(chain[i]!.contract);
        if (!prov || chainParams[i]!.length === 0) continue;
        const names = byProvider.get(prov.providerIdx) ?? [];
        for (const p of chainParams[i]!) {
          if (names.includes(p.name)) {
            this.diags.error(
              prov.site,
              'JETH379',
              `two base constructors initialized by the same contract share the parameter name '${p.name}'; this collides in codegen and is not supported yet (rename one base ctor's parameter)`,
            );
            baseArgsGate = true;
          }
          names.push(p.name);
        }
        byProvider.set(prov.providerIdx, names);
      }
    }

    // Deployed ctor signature: @payable + value-type params (the deploy ABI params = chainParams[0]).
    let payable = false;
    let deployedMods: { name: string; argNodes: ts.Expression[]; site: ts.Node }[] = [];
    const params: Param[] = chainParams[0]!;
    if (deployed.node) {
      const d = this.ctorDecorators(deployed.node);
      payable = d.payable;
      deployedMods = d.ctorMods;
      if (deployed.node.typeParameters && deployed.node.typeParameters.length > 0) {
        this.diags.error(deployed.node, 'JETH301', 'a constructor cannot be generic');
      }
    }

    // Fresh ctor analysis context (mirrors checkConstructor).
    this.scopes = [];
    this.loopDepth = 0;
    this.currentMutability = payable ? 'payable' : 'nonpayable';
    this.currentExternallyReachable = true;
    this.currentWritesState = false;
    this.currentReadsState = false;
    this.currentReadsEnv = false;
    this.currentReturnTypes = undefined;
    this.currentCallees = new Set();
    this.currentInConstructor = true;
    this.memArrayLocals.clear();
    this.memAggregateLocals.clear();
    this.memDynLocals.clear();
    this.memDynStructLocals.clear();

    // ---- NESTED-BLOCK constructor merge (two-phase order, no renaming) ----
    // Build blocks in LINEARIZATION order (most-derived outermost). Net effect: base-ctor ARGUMENT
    // expressions evaluate most-DERIVED-first (outer levels emit their arg localDecls first), and ctor
    // BODIES run most-BASE-first (the innermost level's body executes before the enclosing body that
    // follows it). The analyzer scope stack MIRRORS the codegen block nesting (each `block` Stmt does a
    // ctxPush/ctxPop in yul; freshLocal gives each localDecl a globally-unique Yul name), so each
    // contract's params/body type-check in the correct scope: a base param is visible to its consumers
    // (the nested block) but NOT to the providing contract's OWN body (which is emitted AFTER the
    // block, in the provider's own param scope). Verified body order 101->...->200, args 902->901.
    this.pushScope(); // scope 0: the deployed's formals (= the jeth_constructor params)
    for (const p of params) {
      this.declareLocal(p.name, p.type);
      // the deployed ctor's aggregate params are decoded from the appended creation args into memory
      // (emitConstructor), so they read like @internal memory-reference params (see checkConstructor).
      this.registerAggregateCtorParam(p.name, p.type);
    }

    const buildLevel = (i: number): Stmt[] => {
      const c = chain[i]!;
      const out: Stmt[] = [];
      // (a)+(b): the base params THIS contract provides args for, and the nested block, are wrapped in
      // a block so the base params are scoped to their CONSUMERS (the inner block) and popped before
      // this contract's own body runs (matching Solidity: a base ctor param is not visible in the
      // derived body). The arg expressions are checked in THIS contract's param scope (active now). If
      // this contract supplies NO base args, we DON'T introduce a block (preserving the exact no-arg
      // codegen: the nested entry's body is inlined directly at this level, byte-identical to before).
      const argDecls: Stmt[] = [];
      this.pushScope(); // the bind scope: holds the base param bindings (consumed by the nested block)
      for (const b of c.bases) {
        if (b.args === undefined) continue;
        const prov = baseArgProvider.get(b.name);
        if (!prov || prov.providerIdx !== i) continue; // only the winning provider binds the params
        const targetIdx = chain.findIndex((x) => x.contract === b.name);
        if (targetIdx < 0) continue;
        const bparams = chainParams[targetIdx]!;
        const n = Math.min(bparams.length, prov.argNodes.length);
        for (let k = 0; k < n; k++) {
          // solc: a HERITAGE base-arg expression is evaluated in the inheritance-specifier scope, which
          // sees constants / literals / msg.* / address(this) but NOT any constructor PARAMETER and NOT
          // any STATE variable (both: solc "Undeclared identifier" - state isn't initialized yet). So
          // check each arg with the ctor params HIDDEN (a fresh empty local scope) - a param reference
          // then rejects (JETH072) at parity - AND reject if the expression READS STATE (currentReadsState
          // flips). msg.sender / @constant / address(this) are allowed (they don't read storage). The
          // localDecl init is still LOWERED in this provider's block at codegen (params in an enclosing
          // ctx scope), but a valid program never references a param/state here, so codegen never does.
          const savedArgScopes = this.scopes;
          const savedReadsState = this.currentReadsState;
          this.scopes = [new Map()];
          this.currentReadsState = false;
          const e = this.checkExpr(prov.argNodes[k]!, bparams[k]!.type);
          const init = e ? this.coerce(e, bparams[k]!.type, prov.argNodes[k]!) : undefined;
          if (this.currentReadsState) {
            this.diags.error(
              prov.argNodes[k]!,
              'JETH379',
              `a base-constructor argument for '${b.name}' reads contract state, which is not available in the inheritance clause (state is not yet initialized when base arguments are evaluated); use a constant or constructor-independent expression`,
            );
          }
          this.scopes = savedArgScopes;
          this.currentReadsState = savedReadsState;
          this.declareLocal(bparams[k]!.name, bparams[k]!.type);
          // a base ctor's aggregate param is bound as a memory local (from the coerced base-arg
          // expression), so register it like the deployed aggregate params for the base body's reads.
          this.registerAggregateCtorParam(bparams[k]!.name, bparams[k]!.type);
          argDecls.push({ kind: 'localDecl', name: bparams[k]!.name, type: bparams[k]!.type, init });
        }
      }
      const inner = i + 1 < chain.length ? buildLevel(i + 1) : []; // the next linearization entry, nested
      this.popScope();
      if (argDecls.length) {
        // base params bound here -> wrap [argDecls, nested entry] in a block so they are scoped to the
        // nested bodies only and popped before this contract's own body runs.
        out.push({ kind: 'block', body: [...argDecls, ...inner] });
      } else {
        // no base params bound here -> inline the nested entry directly (no extra block; this is the
        // exact no-arg structure: bodies most-base-first with no wrapping).
        out.push(...inner);
      }
      // (c) this contract's OWN body, checked in its own param scope (base params NOT visible). The
      // deployed's params are scope 0 (declared above); a base's params were bound by an ancestor's
      // wrap block, which still encloses this body at codegen time (providerIdx < i always).
      if (c.node) {
        const cMods = i === 0 ? deployedMods : this.ctorDecorators(c.node).ctorMods;
        let bstmts: Stmt[] = [];
        if (c.node.body) {
          this.pushScope();
          for (const s of c.node.body.statements) this.checkStatement(s, VOID, bstmts);
          this.popScope();
        }
        for (const app of [...cMods].reverse()) bstmts = this.inlineModifier(app, bstmts);
        out.push(...bstmts);
      }
      return out;
    };

    const body: Stmt[] = this.immutableInitStmts();
    if (!baseArgsGate) body.push(...buildLevel(0));
    this.popScope();
    this.currentInConstructor = false;

    // A ctor (or a base ctor in the chain) calling an internal/private function: emitConstructor
    // duplicates the transitively-reachable callees into the creation object. JETH303 is lifted.
    return { params, payable, body };
  }

  // ---- @error / @event declarations ----------------------------------------

  private collectErrorDecl(member: ts.MethodDeclaration): void {
    if (!ts.isIdentifier(member.name)) {
      this.diags.error(member, 'JETH049', 'error name must be a plain identifier');
      return;
    }
    const name = member.name.text;
    // solc reserves the built-in error names Error and Panic: an @error may not redefine them
    // (a same-named @event or function IS allowed, so this guard is specific to @error).
    if (name === 'Error' || name === 'Panic') {
      this.diags.error(
        member,
        'JETH132',
        `@error name '${name}' is reserved: the built-in errors Error and Panic cannot be redefined`,
      );
      return;
    }
    if (member.body) this.diags.error(member, 'JETH125', `@error '${name}' must be a bodyless declaration`);
    if (member.type) this.diags.error(member.type, 'JETH126', `@error '${name}' must not declare a return type`);
    const params: Param[] = [];
    for (const p of member.parameters) {
      if (!ts.isIdentifier(p.name)) {
        this.diags.error(p, 'JETH053', 'parameter name must be a plain identifier');
        continue;
      }
      if (params.some((q) => q.name === (p.name as ts.Identifier).text)) {
        this.diags.error(p, 'JETH053', `duplicate @error parameter name '${p.name.text}'`);
        continue;
      }
      if (decoratorNames(p).includes('indexed')) {
        this.diags.error(
          p,
          'JETH129',
          `@error parameter '${p.name.text}' cannot be @indexed (only event parameters are indexed)`,
        );
      }
      const t = resolveType(p.type, this.diags, this.structsByName);
      if (!t) continue;
      // @error args: static value types, dynamic bytes/string, a DYNAMIC array (G3, head/tail), a
      // STATIC struct / fixed-array (encoded inline in the head, like a non-indexed event param), or
      // a DYNAMIC struct (a head offset + its head/tail blob, like a non-indexed dynamic-struct event
      // param). A struct is allowed regardless of static/dynamic kind; the codegen routes a dynamic
      // struct through encodeDynStructToBlob and a static one inline.
      const errAgg = t.kind === 'struct' || (t.kind === 'array' && t.length !== undefined);
      if (!isStaticValueType(t) && !isBytesLike(t) && !(t.kind === 'array' && t.length === undefined) && !errAgg) {
        this.diags.error(
          p,
          'JETH127',
          `@error parameter '${p.name.text}' has type ${displayName(t)}; supported: static value types, bytes/string, dynamic arrays, static structs/fixed-arrays, and dynamic structs`,
        );
        continue;
      }
      params.push({ name: p.name.text, type: t });
    }
    const strayErr = decoratorNames(member).filter((d) => d !== 'error');
    if (strayErr.length) {
      this.diags.error(
        member,
        'JETH130',
        `@error '${name}' has unsupported decorator(s): ${strayErr.map((d) => '@' + d).join(', ')}`,
      );
    }
    if (this.errorsByName.has(name)) {
      this.diags.error(member, 'JETH128', `duplicate @error declaration '${name}'`);
      return;
    }
    const signature = functionSignature(
      name,
      params.map((p) => p.type),
    );
    const selector = functionSelector(signature);
    const decl: ErrorDecl = { name, params, signature, selector };
    this.errorsByName.set(name, decl);
    this.errors.push(decl);
  }

  private collectEvent(member: ts.MethodDeclaration): void {
    if (!ts.isIdentifier(member.name)) {
      this.diags.error(member, 'JETH049', 'event name must be a plain identifier');
      return;
    }
    const name = member.name.text;
    if (member.body) {
      this.diags.error(member, 'JETH140', `@event '${name}' must be a bodyless declaration`);
      return;
    }
    if (member.type && member.type.kind !== ts.SyntaxKind.VoidKeyword) {
      this.diags.error(member.type, 'JETH141', `@event '${name}' must not declare a return type`);
    }
    const params: EventParam[] = [];
    let indexedCount = 0;
    for (const p of member.parameters) {
      if (!ts.isIdentifier(p.name)) {
        this.diags.error(p, 'JETH053', 'parameter name must be a plain identifier');
        continue;
      }
      if (params.some((q) => q.name === (p.name as ts.Identifier).text)) {
        this.diags.error(p, 'JETH053', `duplicate event parameter name '${p.name.text}'`);
        continue;
      }
      const t = resolveType(p.type, this.diags, this.structsByName);
      if (!t) continue;
      const indexed = decoratorNames(p).includes('indexed');
      if (!isStaticValueType(t)) {
        if (indexed) {
          // an indexed reference-type param becomes a keccak topic. bytes/string: topic =
          // keccak256(content bytes) (G4). A DYNAMIC value-element array: topic =
          // keccak256(element words). A STATIC fixed-array / static struct: topic =
          // keccak256(abi.encode(value)) = keccak over the padded leaf words. All verified vs solc.
          // A supported DYNAMIC struct: topic = keccak256 over the recursively FLATTENED
          // payload (static leaves inline; bytes/string -> content padded to a word, no
          // length; dyn value-array -> element words, no length; nested struct -> members
          // concatenated). Verified byte-identical to solc. A fixed-array-of-dynamic indexed
          // param stays a later step.
          const indexedArrayOk = t.kind === 'array' && t.length === undefined && isStaticValueType(t.element);
          const indexedStaticAgg =
            isStaticType(t) && (t.kind === 'struct' || (t.kind === 'array' && t.length !== undefined));
          const indexedDynStruct = t.kind === 'struct' && this.isSupportedStructReturn(t);
          if (!isBytesLike(t) && !indexedArrayOk && !indexedStaticAgg && !indexedDynStruct) {
            this.diags.error(
              p,
              'JETH207',
              `indexed ${displayName(t)} event parameter '${p.name.text}' is not supported yet (indexed bytes/string, a dynamic value-element array, a static fixed-array/struct, or a supported dynamic struct)`,
            );
            continue;
          }
          // indexed bytes/string, dynamic value array, static fixed-array/struct, or a supported
          // dynamic struct: allowed (keccak topic).
        } else {
          // non-indexed reference param: a dynamic value-element array, bytes/string, a STATIC struct /
          // fixed-array (encoded inline), or a supported DYNAMIC struct (value + bytes/string + dyn
          // value-array fields, encoded as a head offset + head/tail tail). A fixed-array-of-dynamic /
          // nested-dynamic struct field stays a later step.
          const nonIdxDynArray = t.kind === 'array' && t.length === undefined;
          const nonIdxStaticAgg =
            isStaticType(t) && (t.kind === 'struct' || (t.kind === 'array' && t.length !== undefined));
          const nonIdxDynStruct = t.kind === 'struct' && this.isSupportedStructReturn(t);
          if (!isBytesLike(t) && !nonIdxDynArray && !nonIdxStaticAgg && !nonIdxDynStruct) {
            this.diags.error(
              p,
              'JETH142',
              `@event parameter '${p.name.text}' has type ${displayName(t)}; supported: static value types, bytes/string, dynamic value arrays, static structs/fixed-arrays, and dynamic structs (non-indexed)`,
            );
            continue;
          }
        }
      }
      if (indexed) indexedCount++;
      params.push({ name: p.name.text, type: t, indexed });
    }
    // @anonymous events emit no topic0, so all 4 topic slots are available for indexed params.
    const anonymous = decoratorNames(member).includes('anonymous');
    const maxIndexed = anonymous ? 4 : 3;
    if (indexedCount > maxIndexed) {
      this.diags.error(
        member,
        'JETH143',
        `@event '${name}' has ${indexedCount} indexed parameters (max ${maxIndexed}${anonymous ? ' for an anonymous event' : ''})`,
      );
    }
    // Only @event/@anonymous are meaningful on an event declaration (solc rejects other modifiers).
    const stray = decoratorNames(member).filter((d) => d !== 'event' && d !== 'anonymous');
    if (stray.length) {
      this.diags.error(
        member,
        'JETH145',
        `@event '${name}' has unsupported decorator(s): ${stray.map((d) => '@' + d).join(', ')}`,
      );
    }
    // solc allows event overloading by signature (name + parameter types); only an EXACT duplicate
    // signature is an error.
    const signature = functionSignature(
      name,
      params.map((p) => p.type),
    );
    const overloads = this.eventsByName.get(name) ?? [];
    if (overloads.some((e) => e.signature === signature)) {
      this.diags.error(member, 'JETH144', `duplicate @event declaration '${signature}'`);
      return;
    }
    const topic0 = eventTopic0(signature);
    const ev: EventIR = { name, params, signature, topic0, anonymous };
    this.eventsByName.set(name, [...overloads, ev]);
    this.events.push(ev);
  }

  private collectStateVar(member: ts.PropertyDeclaration, out: RawStateVar[]): void {
    const decs = decoratorNames(member);
    const isConstant = decs.includes('constant');
    const isImmutable = decs.includes('immutable');
    const isStorage = decs.includes('storage');
    // @storage('ns'): an ERC-7201 namespaced storage field (an alternative to @state). It cannot
    // combine with @state/@constant/@immutable (each is its own slot model), and it carries EXACTLY
    // one non-empty string-literal namespace argument. Once validated, it flows through the SAME
    // field validation/layout as @state, just routed to the namespace's raw list (planNamespacedStorage).
    let namespace: string | undefined;
    if (isStorage) {
      if (isConstant || isImmutable || decs.includes('state')) {
        const other = isConstant ? 'constant' : isImmutable ? 'immutable' : 'state';
        this.diags.error(member, 'JETH409', `a field cannot combine @storage with @${other}`);
        return;
      }
      const nsArg = this.storageNamespaceArg(member);
      if (nsArg === undefined) return;
      namespace = nsArg.ns;
      if (nsArg.raw) this.rawNamespaces.add(nsArg.ns);
    }
    if (!decs.includes('state') && !isConstant && !isImmutable && !isStorage) {
      this.diags.error(
        member,
        'JETH045',
        "contract fields must be marked @state (or @constant / @immutable / @storage('ns'))",
      );
      return;
    }
    const kinds = [decs.includes('state') && 'state', isConstant && 'constant', isImmutable && 'immutable'].filter(
      Boolean,
    );
    if (kinds.length > 1) {
      this.diags.error(member, 'JETH052', `a field cannot combine @${kinds.join(' and @')}`);
      return;
    }
    if (!ts.isIdentifier(member.name)) {
      this.diags.error(
        member,
        'JETH046',
        `${isConstant ? 'constant' : isImmutable ? 'immutable' : 'state variable'} name must be a plain identifier`,
      );
      return;
    }
    if (isConstant) {
      this.collectConstant(member);
      return;
    }
    if (isImmutable) {
      this.collectImmutable(member);
      return;
    }
    const type = resolveType(member.type, this.diags, this.structsByName);
    if (!type) return;
    if (type.kind === 'void') {
      this.diags.error(member, 'JETH047', 'state variable cannot be void');
      return;
    }
    if (!this.gateArrayType(type, member, true)) return;
    // string[]/bytes[] (array of dynamic elements) in storage: the bare array, or a
    // mapping<K, string[]> value, mirrors solc (length at slot p / keccak(key.base);
    // element header i at keccak(lenSlot)+i, a normal storage bytes/string). A
    // string[] nested deeper (struct field, string[][], element of another array) is
    // still a later step: containsDynElemArray catches those and stays gated.
    // Storage nested dynamic arrays (u256[][], string[][], D[][], ...) and dyn-array
    // struct fields are supported via per-inner data slots: an inner array's length lives
    // at the AccessPath slot (placeArray), data at keccak(that slot), recursively. So the
    // earlier string[][] / T[][] storage gates are lifted; gateArrayType still rejects
    // genuinely-unrepresentable element kinds.
    // A DYNAMIC STRUCT (a @struct with >=1 bytes/string or nested-dynamic-struct
    // field) is now supported in storage / as a mapping value: each static field
    // uses normal packed storage and each bytes/string field at base+fieldSlot is a
    // normal storage bytes/string (byte-identical to solc, verified incl. raw
    // slots). A dynamic struct in a form we do NOT yet implement (e.g. buried in a
    // fixed array, though gateArrayType already rejects those element kinds) stays
    // gated rather than silently miscompiled.
    if (this.containsDynamicStruct(type) && !this.isStorageDynStruct(type)) {
      this.diags.error(
        member,
        'JETH231',
        'storage dynamic struct in this position is not supported yet (supported: a bare @state d: D, or a mapping<K, D> value, where D is a @struct with bytes/string fields; a dynamic array of dynamic struct D[] / fixed Arr<D,N> is rejected separately)',
      );
      return;
    }

    let initialValue: bigint | boolean | undefined;
    if (member.initializer) {
      const folded = this.foldConstant(member.initializer, type);
      if (folded === undefined) {
        this.diags.error(
          member.initializer,
          'JETH048',
          'state initializer must be a constant expression (non-constant init requires a constructor, Phase 5)',
        );
      } else if (folded !== 0n && folded !== false) {
        initialValue = folded; // zero/false is the storage default; no SSTORE needed
      }
    }
    if (decs.includes('external')) this.publicStateNames.add(member.name.text); // @external @state/@storage -> auto-generated getter
    if (namespace !== undefined) {
      // Route to the namespace's raw list; planNamespacedStorage lays each ns out from slot 0 and
      // offsets by base(ns). Kept OUT of `out` (rawState) so @storage never shifts an @state slot.
      const list = this.namespacedStorage.get(namespace) ?? [];
      list.push({ name: member.name.text, type, initialValue });
      this.namespacedStorage.set(namespace, list);
      return;
    }
    out.push({ name: member.name.text, type, initialValue });
  }

  /** Validate a `@storage('ns')` decorator's argument: a non-empty string-literal namespace, with an
   *  OPTIONAL second string-literal mode `'raw'` (synthesis-only: the diamond struct's raw-keccak base).
   *  A user `@storage('ns')` takes exactly one arg (raw is reserved for the synthesized @diamond).
   *  Returns `{ ns, raw }`, or undefined after reporting a clean diagnostic. */
  private storageNamespaceArg(member: ts.PropertyDeclaration): { ns: string; raw: boolean } | undefined {
    const call = decoratorCall(member, 'storage');
    if (!call) {
      this.diags.error(member, 'JETH410', "@storage requires a namespace argument: @storage('my.namespace')");
      return undefined;
    }
    if (call.arguments.length < 1 || call.arguments.length > 2) {
      this.diags.error(call, 'JETH410', '@storage takes a string-literal namespace argument');
      return undefined;
    }
    const arg = call.arguments[0]!;
    if (!ts.isStringLiteralLike(arg)) {
      this.diags.error(arg, 'JETH410', '@storage namespace must be a string literal');
      return undefined;
    }
    if (arg.text.length === 0) {
      this.diags.error(arg, 'JETH410', '@storage namespace must be a non-empty string');
      return undefined;
    }
    let raw = false;
    if (call.arguments.length === 2) {
      const mode = call.arguments[1]!;
      if (!ts.isStringLiteralLike(mode) || mode.text !== 'raw') {
        this.diags.error(mode, 'JETH410', "@storage's optional second argument must be the literal 'raw'");
        return undefined;
      }
      raw = true;
    }
    return { ns: arg.text, raw };
  }

  /** ERC-7201 (EIP-7201) namespaced-storage base slot for `ns`:
   *    base = keccak256(abi.encode(uint256(keccak256(bytes(ns))) - 1)) & ~bytes32(uint256(0xff))
   *  i.e. inner = keccak256(utf8 bytes of ns) as a uint256; minus 1 (mod 2^256); abi.encode of that
   *  uint256 is its 32-byte big-endian word; keccak256 of that word; then clear the low byte. Computed
   *  at compile time so the namespaced slots match a hand-written solc ERC-7201 struct byte-for-byte. */
  private erc7201Base(ns: string): bigint {
    const M = 1n << 256n;
    const inner = BigInt('0x' + toHex(keccak(ns))); // keccak256(bytes(ns)) as uint256
    const minus = (inner - 1n + M) % M; // uint256(inner) - 1 (mod 2^256)
    // abi.encode(uint256(minus)) is its 32-byte big-endian word.
    const word = new Uint8Array(32);
    let x = minus;
    for (let i = 31; i >= 0; i--) {
      word[i] = Number(x & 0xffn);
      x >>= 8n;
    }
    const hashed = BigInt('0x' + toHex(keccak(word)));
    return hashed & ~0xffn; // & ~bytes32(uint256(0xff)): clear the low byte
  }

  /** Lay out every `@storage('ns')` namespace and return its fields as StateVars at their absolute
   *  slots. Each namespace is laid out from slot 0 by the SAME planLayout (sequential + packing) as
   *  @state, then each field's slot is OFFSET by base(ns). Distinct namespaces are isolated (their own
   *  keccak base); these vars live in a slot space DISJOINT from @state's sequential 0.. space. */
  private planNamespacedStorage(): StateVar[] {
    const result: StateVar[] = [];
    for (const [ns, raw] of this.namespacedStorage) {
      // The synthesized @diamond struct uses the RAW keccak256(ns) base (mudgen's
      // DIAMOND_STORAGE_POSITION = keccak256("diamond.standard.diamond.storage")); a user
      // @storage('ns') uses the ERC-7201 (-1, re-hash, clear-low-byte) base.
      const base = this.rawNamespaces.has(ns) ? BigInt('0x' + toHex(keccak(ns))) : this.erc7201Base(ns);
      const layout = planLayout(raw); // sequential + packing within the namespace, from slot 0
      for (const v of layout.vars) {
        result.push({
          name: v.name,
          type: v.type,
          slot: base + BigInt(v.slot),
          offset: v.offset,
          initialValue: v.initialValue,
        });
      }
    }
    return result;
  }

  // A `@constant` is a slot-free compile-time constant (solc's `type constant NAME = value`): the
  // folded literal is substituted at each read site, it consumes NO storage slot, and it is absent
  // from the ABI (solc generates no getter for a constant). Scoped to value-type constants
  // (uintN/intN/bool/address/bytesN); a bytes/string/aggregate constant stays a clean over-rejection.
  private collectConstant(member: ts.PropertyDeclaration): void {
    const name = (member.name as ts.Identifier).text;
    const type = resolveType(member.type, this.diags, this.structsByName);
    if (!type) return;
    // Folding supports integer + bool + address + bytesN + string constants. A bytes/aggregate
    // constant stays a clean over-rejection (a later step), not a confusing fold-failure cascade.
    if (
      type.kind !== 'uint' &&
      type.kind !== 'int' &&
      type.kind !== 'bool' &&
      type.kind !== 'address' &&
      type.kind !== 'bytesN' &&
      type.kind !== 'string'
    ) {
      this.diags.error(
        member,
        'JETH050',
        `@constant ${displayName(type)} is not supported yet (only uintN/intN/bool/address/bytesN/string constants)`,
      );
      return;
    }
    if (!member.initializer) {
      this.diags.error(member, 'JETH048', `@constant '${name}' requires a constant initializer`);
      return;
    }
    if (this.constantsByName.has(name) || this.stateByName.has(name) || this.immutablesByName.has(name)) {
      this.diags.error(member, 'JETH046', `duplicate @constant '${name}'`);
      return;
    }
    if (type.kind === 'string') {
      // a string constant must be a string literal (solc: only a literal); store the UTF-8 bytes,
      // substituted as a fresh memory string at each read site.
      const init = member.initializer;
      if (!ts.isStringLiteral(init) && !ts.isNoSubstitutionTemplateLiteral(init)) {
        this.diags.error(init, 'JETH048', `@constant '${name}' must be a string literal`);
        return;
      }
      this.constantsByName.set(name, { value: new TextEncoder().encode(init.text), type });
      return;
    }
    const folded = this.foldConstant(member.initializer, type);
    if (folded === undefined) {
      this.diags.error(member.initializer, 'JETH048', `@constant '${name}' initializer must be a constant expression`);
      return;
    }
    this.constantsByName.set(name, { value: folded, type });
  }

  // An `@immutable` is a value-type field assigned once in the constructor and baked into the
  // runtime code via setimmutable (read via loadimmutable). It consumes NO storage slot (it never
  // enters rawState, so the planner numbers @state vars exactly as solc does). Scoped to value types
  // (uintN/intN/bool/address/bytesN/enum/branded) - solc itself rejects a non-value-type immutable.
  private collectImmutable(member: ts.PropertyDeclaration): void {
    const name = (member.name as ts.Identifier).text;
    const decs = decoratorNames(member);
    // An `@external @immutable` mirrors solc's `public immutable`: a view getter is auto-generated
    // (name() view returns (T), reading the immutable via loadimmutable - NO storage slot). It is
    // synthesized in analyzeContract (see publicImmutableNames). The OTHER visibility/mutability
    // decorators are nonsensical on an immutable (no parameterized getter, no storage) and stay gated.
    const extra = ['public', 'internal', 'private', 'view', 'pure', 'payable', 'read', 'hidden'].find((d) =>
      decs.includes(d),
    );
    if (extra) {
      this.diags.error(
        member,
        'JETH312',
        `@immutable '${name}' cannot also be @${extra} (only @external is allowed, synthesizing solc's public-immutable view getter; for any other visibility expose it with an explicit @view function)`,
      );
      return;
    }
    if (decs.includes('external')) this.publicImmutableNames.add(name); // @external @immutable -> auto-generated view getter
    const type = resolveType(member.type, this.diags, this.structsByName);
    if (!type) return;
    if (!isStaticValueType(type)) {
      this.diags.error(
        member,
        'JETH310',
        `@immutable '${name}' of type ${displayName(type)} is not supported (immutables must be a value type: uintN/intN/bool/address/bytesN/enum/branded)`,
      );
      return;
    }
    // Inline initialization (`@immutable a: u256 = 7n`) is staged as an assignment at the START of the
    // constructor (a synthetic one is created when the contract has no constructor), matching solc.
    if (this.immutablesByName.has(name) || this.constantsByName.has(name) || this.stateByName.has(name)) {
      this.diags.error(member, 'JETH046', `duplicate field name '${name}'`);
      return;
    }
    this.immutablesByName.set(name, { name, type, init: member.initializer });
    this.immutableOrder.push(name);
  }

  private collectFunction(member: ts.MethodDeclaration): RawFunction | undefined {
    if (!ts.isIdentifier(member.name)) {
      this.diags.error(member, 'JETH049', 'method name must be a plain identifier');
      return undefined;
    }
    const decs = decoratorNames(member);

    // Phase 5: capture APPLIED @modifier decorators (e.g. @onlyOwner / @minVal(amount)) in source
    // order (leftmost = outermost). A decorator whose name is not a built-in function decorator is a
    // candidate modifier application; it is resolved against modifiersByName in checkFunction (an
    // unknown name -> JETH329). The decorator's call-form arguments are captured for inlining.
    const BUILTIN_FN_DECORATORS = new Set([
      'external',
      'public',
      'internal',
      'private',
      'view',
      'pure',
      'payable',
      'read',
      'hidden',
      'nonReentrant',
      'modifier',
      'error',
      'event',
      // inheritance: @virtual / @override (bare or @override(B,C)) are not @modifier applications.
      'virtual',
      'override',
      // Phase 6: @receive / @fallback special runtime entries (handled in analyzeContract, not here).
      'receive',
      'fallback',
    ]);
    const appliedModifiers: { name: string; argNodes: ts.Expression[]; site: ts.Node }[] = [];
    for (const d of ts.getDecorators(member) ?? []) {
      const e = d.expression;
      if (ts.isIdentifier(e) && !BUILTIN_FN_DECORATORS.has(e.text)) {
        appliedModifiers.push({ name: e.text, argNodes: [], site: d });
      } else if (
        ts.isCallExpression(e) &&
        ts.isIdentifier(e.expression) &&
        !BUILTIN_FN_DECORATORS.has(e.expression.text)
      ) {
        appliedModifiers.push({ name: e.expression.text, argNodes: [...e.arguments], site: d });
      }
    }

    // Inheritance metadata: @virtual / @override (bare or @override(B, C)). A bodyless method is an
    // unimplemented @virtual (a base abstract method). The explicit base list of @override(B, C)
    // (the diamond redefinition list) is captured for the diamond completeness check. Spread into
    // every RawFunction this method returns.
    const overrideCall = decoratorCall(member, 'override');
    let overrideList: string[] | undefined;
    if (overrideCall && overrideCall.arguments.length > 0) {
      overrideList = overrideCall.arguments.map((a) => (ts.isIdentifier(a) ? a.text : a.getText()));
    }
    const inhMeta = {
      isVirtual: decs.includes('virtual'),
      isOverride: decs.includes('override'),
      overrideList,
      bodyless: member.body === undefined,
    };

    // VISIBILITY MODEL: the ONLY writable visibility decorator is @external (an exposed ABI entry).
    // A function WITHOUT @external is INTERNAL (private-by-default: callable by name, memory params,
    // never in the ABI). @public/@internal/@private/@hidden are no longer writable - the compiler owns
    // the internal-side decision (private now; private vs internal inferred from cross-contract use once
    // inheritance lands). This dissolves the dual external+internal ("public") function entirely.
    const removedVis = ['public', 'internal', 'private', 'hidden'].find((d) => decs.includes(d));
    if (removedVis) {
      this.diags.error(
        member,
        'JETH054',
        `@${removedVis} is not a JETH visibility decorator: write @external to expose a function; everything else is internal by default (the compiler infers private/internal)`,
      );
    }
    const visibility: Visibility = decs.includes('external') ? 'external' : 'internal';

    // MUTABILITY INFERENCE: `@read` is a read-only function whose @pure/@view is computed from
    // its TRANSITIVE effects after the fixpoint. Provisionally @view so the body is validated as
    // read-only (no writes/emits/msg.value); an actual write is rejected (JETH056).
    const read = decs.includes('read');
    // A function is at most one of @view/@pure/@payable (solc: "State mutability already specified").
    const explicitMuts = (['view', 'pure', 'payable'] as const).filter((m) => decs.includes(m));
    if (!read && explicitMuts.length > 1) {
      this.diags.error(
        member,
        'JETH052',
        `conflicting mutability decorators: ${explicitMuts.map((m) => '@' + m).join(', ')} (a function is at most one of @view/@pure/@payable)`,
      );
    }
    let mutability: Mutability = 'nonpayable';
    let inferRead = false;
    if (read) {
      const explicitMut = ['view', 'pure', 'payable'].filter((m) => decs.includes(m));
      if (explicitMut.length > 0)
        this.diags.error(member, 'JETH052', `conflicting mutability: @read with @${explicitMut[0]}`);
      mutability = 'view';
      inferRead = true;
    } else if (decs.includes('payable')) mutability = 'payable';
    else if (decs.includes('view')) mutability = 'view';
    else if (decs.includes('pure')) mutability = 'pure';
    // solc: internal/private functions can never be payable (no message context of their own).
    // @hidden is an explicitly-internal function, so it is rejected with @payable too.
    if (decs.includes('payable') && !decs.includes('external')) {
      this.diags.error(
        member,
        'JETH131',
        '@payable requires @external (an internal function has no message-call value context of its own)',
      );
    }

    // F4: @nonReentrant wraps the external entry in a transient-storage mutex. It must be a
    // state-mutating external/public function: a guard performs a TSTORE, so @read/@view/@pure
    // are incompatible, and reentrancy only meaningfully protects externally-reachable entries.
    const nonReentrant = decs.includes('nonReentrant');
    if (nonReentrant) {
      if (read || decs.includes('view') || decs.includes('pure')) {
        this.diags.error(
          member,
          'JETH260',
          '@nonReentrant cannot be combined with @read/@view/@pure (a reentrancy guard writes transient storage; the function must be state-mutating)',
        );
      }
      if (!decs.includes('external')) {
        this.diags.error(
          member,
          'JETH261',
          '@nonReentrant requires an @external function (a reentrancy guard protects an externally-reachable entry)',
        );
      }
    }

    const params: { name: string; type: JethType }[] = [];
    const defaults: (ts.Expression | undefined)[] = [];
    let seenDefault = false;
    for (const p of member.parameters) {
      if (!ts.isIdentifier(p.name)) {
        this.diags.error(p, 'JETH053', 'parameter name must be a plain identifier');
        continue;
      }
      const t = resolveType(p.type, this.diags, this.structsByName);
      if (!t) continue;
      // A type containing a mapping is storage-only: it cannot be a parameter (matches solc).
      if (this.typeHasMapping(t)) {
        this.diags.error(
          p,
          'JETH247',
          `parameter '${p.name.text}' of type ${displayName(t)} contains a mapping and cannot be passed (mappings are storage-only)`,
        );
        continue;
      }
      if (!this.gateArrayType(t, p)) continue;
      // F3: a default value (b: u256 = 10n) is a CALL-SITE fill for an omitted internal arg.
      // It must be a self-contained constant (no scope dependency), and any defaulted param
      // must be trailing (no required param may follow one). Defaults never reach the ABI or
      // codegen; external callers always provide every argument.
      let def: ts.Expression | undefined;
      if (p.initializer) {
        if (!isStaticValueType(t)) {
          this.diags.error(
            p,
            'JETH252',
            `parameter '${p.name.text}' of type ${displayName(t)} cannot have a default value (only value types)`,
          );
        } else if (!this.isConstDefault(p.initializer)) {
          this.diags.error(
            p.initializer,
            'JETH250',
            `default for '${p.name.text}' must be a constant literal (e.g. 10n, true, address(0n), type(u256).max)`,
          );
        } else {
          def = p.initializer;
          seenDefault = true;
        }
      } else if (seenDefault) {
        this.diags.error(p, 'JETH251', `parameter '${p.name.text}' (no default) cannot follow a defaulted parameter`);
      }
      // Static struct / fixed-array params decode lazily from the ABI-unpacked head
      // via CalldataPlace; a DYNAMIC struct param (>=1 dynamic field, Phase 4e-6)
      // decodes via its tuple head/tail (CdDynPlace). Both shapes resolve OK here;
      // unsupported field kinds were rejected at @struct declaration (JETH229).
      params.push({ name: p.name.text, type: t });
      defaults.push(def);
    }

    // multi-value return `f(): [T1, T2, ...]` (a TS tuple type). Each component is a
    // value or bytes/string type (one ABI head word each); aggregate components are a
    // later step.
    if (member.type && ts.isTupleTypeNode(member.type)) {
      const returnTypes: JethType[] = [];
      let ok = true;
      for (const el of member.type.elements) {
        const t = resolveType(el, this.diags, this.structsByName);
        if (!t) {
          ok = false;
          break;
        }
        if (t.kind === 'mapping' || t.kind === 'void') {
          this.diags.error(el, 'JETH213', 'a multi-value return component cannot be a mapping or void');
          ok = false;
          break;
        }
        returnTypes.push(t);
      }
      if (ok && returnTypes.length >= 2) {
        return {
          node: member,
          name: member.name.text,
          visibility,
          mutability,
          inferRead,
          nonReentrant,
          modifiers: appliedModifiers.length ? appliedModifiers : undefined,
          ...inhMeta,
          params,
          defaults,
          returnType: VOID,
          returnTypes,
        };
      }
      return {
        node: member,
        name: member.name.text,
        visibility,
        mutability,
        inferRead,
        nonReentrant,
        modifiers: appliedModifiers.length ? appliedModifiers : undefined,
        ...inhMeta,
        params,
        defaults,
        returnType: VOID,
      };
    }

    const returnType = member.type ? (resolveType(member.type, this.diags, this.structsByName) ?? VOID) : VOID;
    if (this.typeHasMapping(returnType)) {
      this.diags.error(
        member.type ?? member,
        'JETH247',
        `return type ${displayName(returnType)} contains a mapping and cannot be returned (mappings are storage-only)`,
      );
    } else if (returnType.kind === 'struct' && !this.isSupportedStructReturn(returnType)) {
      this.diags.error(
        member.type ?? member,
        'JETH225',
        'returning a struct with this shape is not supported yet (supported: static value/nested-static-struct fields, and bytes/string or nested-struct dynamic fields)',
      );
    }
    if (!this.gateArrayType(returnType, member.type ?? member)) {
      return {
        node: member,
        name: member.name.text,
        visibility,
        mutability,
        inferRead,
        nonReentrant,
        modifiers: appliedModifiers.length ? appliedModifiers : undefined,
        ...inhMeta,
        params,
        defaults,
        returnType: VOID,
      };
    }

    return {
      node: member,
      name: member.name.text,
      visibility,
      mutability,
      inferRead,
      nonReentrant,
      modifiers: appliedModifiers.length ? appliedModifiers : undefined,
      ...inhMeta,
      params,
      defaults,
      returnType,
    };
  }

  // ---- F6: compile-time generics (monomorphization) ------------------------

  /** Validate and register a generic function template `f<T, ...>(...)`. The decl shape is
   *  checked here (internal-only, plain-identifier type params with no constraints); the body
   *  and signature are NOT collected now - each concrete instantiation is synthesized lazily at
   *  its call site and flows through the normal collect/check/emit internal-function pipeline. */
  private collectGeneric(member: ts.MethodDeclaration): void {
    if (!ts.isIdentifier(member.name)) {
      this.diags.error(member, 'JETH049', 'method name must be a plain identifier');
      return;
    }
    const name = member.name.text;
    const decs = decoratorNames(member);
    // A generic is callable ONLY internally (its specializations are internal functions and never
    // reach the ABI), so an explicit @external/@public is an error - the ABI cannot be generic.
    if (decs.includes('external') || decs.includes('public')) {
      this.diags.error(
        member,
        'JETH290',
        `generic function '${name}' cannot be @external/@public (its type is not expressible in the ABI); make it internal (@internal/@private/@hidden, or no visibility decorator)`,
      );
    }
    if (decs.includes('nonReentrant')) {
      this.diags.error(
        member,
        'JETH290',
        `generic function '${name}' cannot be @nonReentrant (a generic is internal-only and the reentrancy guard protects an external entry)`,
      );
    }
    const typeParams: string[] = [];
    for (const tp of member.typeParameters!) {
      if (tp.constraint || tp.default) {
        this.diags.error(
          tp,
          'JETH294',
          `type parameter '${tp.name.text}' must be a plain identifier (constraints / defaults are not supported)`,
        );
      }
      const pn = tp.name.text;
      if (resolvePrimitiveName(pn) || this.structsByName.has(pn)) {
        this.diags.error(tp, 'JETH294', `type parameter name '${pn}' conflicts with an existing type`);
      }
      if (typeParams.includes(pn)) {
        this.diags.error(tp, 'JETH294', `duplicate type parameter '${pn}' in generic '${name}'`);
      }
      typeParams.push(pn);
    }
    if (this.genericsByName.has(name) || this.funcsByName.has(name)) {
      this.diags.error(member, 'JETH295', `function '${name}' redeclared`);
      return;
    }
    this.genericsByName.set(name, { node: member, typeParams });
  }

  /** Register each type-parameter -> concrete-type binding in structsByName for the duration of
   *  `fn` (so resolveType resolves T to its concrete JethType while collecting/checking one
   *  specialization), restoring any name it shadowed afterwards. */
  private withTypeBinding<R>(binding: Map<string, JethType>, fn: () => R): R {
    const saved: [string, JethType | undefined][] = [];
    for (const [tp, ct] of binding) {
      saved.push([tp, this.structsByName.get(tp)]);
      this.structsByName.set(tp, ct);
    }
    try {
      return fn();
    } finally {
      for (const [tp, prev] of saved) {
        if (prev === undefined) this.structsByName.delete(tp);
        else this.structsByName.set(tp, prev);
      }
    }
  }

  /** A unique, valid-identifier mangled name for `f` specialized at the given concrete types.
   *  Distinct from any user function name (the `$` separators are illegal in a TS identifier, so a
   *  user could never declare a colliding name) and one-to-one with the type tuple, so it doubles
   *  as the specialization cache KEY: two instantiations with the same concrete types collapse to
   *  one specialization (dedup). The per-type tag includes the BRAND (a branded newtype / enum is a
   *  DISTINCT nominal type from its base), so `f<Wei>` and `f<u256>` are separate specializations
   *  even though their runtime codegen is byte-identical. */
  private mangleSpecialization(name: string, args: JethType[]): string {
    const tag = (t: JethType): string => {
      const br = (t as { brand?: string }).brand;
      // a brand name is a user identifier (already [A-Za-z0-9_], no primitive collisions); prefix
      // with `b_` so a brand can never alias a base canonical tag (e.g. a brand named `uint256`).
      const base = canonicalName(t).replace(/[^A-Za-z0-9]/g, '_');
      return br ? `b_${br}_${base}` : base;
    };
    return `${name}$${args.map(tag).join('$')}`;
  }

  /** Resolve the concrete type arguments for a generic call: explicit `f<u256>(x)` from the call
   *  node's `typeArguments`, otherwise inferred by matching each parameter annotated with a bare
   *  type-parameter identifier against the corresponding checked argument's concrete type. Returns
   *  the binding (typeParam -> JethType) or undefined (after emitting a diagnostic). */
  private resolveGenericTypeArgs(
    node: ts.CallExpression,
    gen: { node: ts.MethodDeclaration; typeParams: string[] },
    name: string,
  ): Map<string, JethType> | undefined {
    const binding = new Map<string, JethType>();
    const params = gen.node.parameters;

    if (node.typeArguments && node.typeArguments.length > 0) {
      // EXPLICIT type arguments: `this.f<u256, address>(...)`.
      if (node.typeArguments.length !== gen.typeParams.length) {
        this.diags.error(
          node,
          'JETH292',
          `generic '${name}' expects ${gen.typeParams.length} type argument(s), got ${node.typeArguments.length}`,
        );
        return undefined;
      }
      for (let i = 0; i < gen.typeParams.length; i++) {
        const t = resolveType(node.typeArguments[i]!, this.diags, this.structsByName);
        if (!t) return undefined;
        if (!this.gateGenericTypeArg(t, node.typeArguments[i]!, gen.typeParams[i]!)) return undefined;
        binding.set(gen.typeParams[i]!, t);
      }
      return binding;
    }

    // INFERENCE: bind each type parameter that appears as a bare-identifier parameter annotation
    // to that argument's concrete type. A parameter `x: T` where T is a type-param infers T; a
    // type param used only in the return type (or never in a bare-identifier param) cannot be
    // inferred. Unify across params: a conflict (T inferred as two different types) is an error.
    const argNodes = node.arguments;
    for (let i = 0; i < params.length && i < argNodes.length; i++) {
      const ann = params[i]!.type;
      if (!ann || !ts.isTypeReferenceNode(ann) || !ts.isIdentifier(ann.typeName)) continue;
      const tpName = ann.typeName.text;
      if (!gen.typeParams.includes(tpName)) continue;
      const a = this.checkExpr(argNodes[i]!);
      if (!a) return undefined;
      // strip a leading branded identity only when inferring? No: infer the EXACT concrete type
      // (a branded value infers its brand), matching how the body would re-resolve T.
      const inferred = a.type;
      const prev = binding.get(tpName);
      if (prev && !typesEqual(prev, inferred)) {
        this.diags.error(
          argNodes[i]!,
          'JETH293',
          `conflicting type arguments inferred for '${tpName}' in '${name}': ${displayName(prev)} vs ${displayName(inferred)} (specify it explicitly, e.g. ${name}<${displayName(prev)}>(...))`,
        );
        return undefined;
      }
      if (!prev) binding.set(tpName, inferred);
    }

    for (const tp of gen.typeParams) {
      if (!binding.has(tp)) {
        this.diags.error(
          node,
          'JETH292',
          `cannot infer type argument ${tp} for '${name}'; specify it explicitly, e.g. ${name}<u256>(...)`,
        );
        return undefined;
      }
      if (!this.gateGenericTypeArg(binding.get(tp)!, node, tp)) return undefined;
    }
    return binding;
  }

  /** A concrete type argument must be a VALUE type (uintN/intN/bool/address/bytesN/enum/branded).
   *  A reference type (struct/array/mapping/bytes/string) is rejected (JETH291). (Internal struct
   *  params exist but generic struct type-arguments are a future extension.) */
  private gateGenericTypeArg(t: JethType, node: ts.Node, tp: string): boolean {
    if (isStaticValueType(t)) return true; // covers uintN/intN/bool/address/bytesN, incl. enums + branded (a branded value type is one of these with a brand)
    this.diags.error(
      node,
      'JETH291',
      `type argument for '${tp}' must be a value type (uintN/intN/bool/address/bytesN/enum/branded newtype), got ${displayName(t)}`,
    );
    return false;
  }

  /** Resolve a generic call: compute its concrete instantiation, synthesize (once) a mangled
   *  non-generic specialization that flows through the normal internal-function pipeline, and emit
   *  the call as an ordinary internal call to that mangled name. Returns undefined on error. */
  private checkGenericCall(
    node: ts.CallExpression,
    name: string,
    asStatement: boolean,
  ): (Expr & { kind: 'call' }) | undefined {
    const gen = this.genericsByName.get(name)!;
    const binding = this.resolveGenericTypeArgs(node, gen, name);
    if (!binding) return undefined;
    const args = gen.typeParams.map((tp) => binding.get(tp)!);
    const key = this.mangleSpecialization(name, args);

    if (!this.specializedNames.has(key)) {
      // The mangled name embeds `$`, which is a legal identifier char, so in the pathological case a
      // user declared a non-generic function with the exact mangled name we reject it with a clear
      // diagnostic rather than letting two Yul defs collide (which would surface as a backend ICE).
      if (this.funcsByName.has(key) || this.genericsByName.has(key)) {
        this.diags.error(
          node,
          'JETH296',
          `specialization name '${key}' for generic '${name}' collides with an existing function; rename that function`,
        );
        return undefined;
      }
      // First time this exact instantiation is seen. Synthesize a non-generic RawFunction by
      // collecting the SAME AST node with the type params bound to their concrete types, then give
      // it the mangled name. Register it in funcsByName + the cache BEFORE its body is checked, so a
      // recursive self-call at the same T finds the in-progress specialization (no infinite loop).
      this.specializedNames.set(key, key);
      const rf = this.withTypeBinding(binding, () => this.collectFunction(gen.node));
      if (!rf) {
        // collectFunction emitted a diagnostic (e.g. a param type invalid for this instantiation).
        this.specializedNames.delete(key);
        return undefined;
      }
      // Force a concrete internal visibility (a specialization is never in the ABI) and a stable
      // mangled name; drop any visibility inference (a generic is internal by construction).
      rf.name = key;
      rf.visibility = 'internal';
      this.funcsByName.set(key, rf);
      this.specializationQueue.push({ mangled: key, node: gen.node, binding });
    }

    // Emit the call as an ordinary internal call to the mangled specialization. Argument checking,
    // coercion, and the call IR all reuse the existing internal-call path; arg types are checked
    // against the specialization's (already concrete) parameter types.
    return this.checkInternalCall(node, key, asStatement);
  }

  private checkFunction(rf: RawFunction): FunctionIR | undefined {
    this.scopes = [];
    this.loopDepth = 0;
    this.currentDefiningContract = rf.definingContract; // inheritance: scope super.f() to this contract
    this.pushScope(); // function/parameter scope
    this.currentMutability = rf.mutability;
    // only @external is externally reachable; an unmarked (internal) function is not. Gates the
    // msg.value/@payable rule.
    this.currentExternallyReachable = rf.visibility === 'external';
    this.currentWritesState = false;
    this.currentReadsState = false;
    this.currentReadsEnv = false;
    this.currentReturnTypes = rf.returnTypes;
    this.currentCallees = new Set();
    this.memArrayLocals.clear();
    this.memAggregateLocals.clear();
    this.memDynLocals.clear();
    this.memDynStructLocals.clear();
    // A buffered-modifier function (a post-code / conditional-placeholder / multi-placeholder / return;
    // modifier applied) has its BODY emitted as a synthesized internal function userfn_<key> that the
    // dispatch calls with each aggregate param passed BY MEMORY REFERENCE (JETH323). So its body's
    // aggregate params resolve to MEMORY places exactly like an @internal function's, even though the
    // function is @external (the buffered path is gated to @external). Treat it as internalOnly for the
    // param-memory registration below.
    const bufferedModifier = this.usesBufferedModifierPath(rf);
    const internalOnly = rf.visibility === 'internal' || rf.visibility === 'private' || bufferedModifier;
    for (const p of rf.params) {
      if (this.inCurrentScope(p.name)) {
        this.diags.error(rf.node, 'JETH056', `duplicate parameter name '${p.name}'`);
      }
      this.declareLocal(p.name, p.type);
      // G9: a STATIC struct param of an @internal/@private function is a MEMORY pointer
      // (passed by reference), so `p.x` resolves to a memory field, not a calldata place.
      if (internalOnly && p.type.kind === 'struct' && isStaticType(p.type)) {
        this.memAggregateLocals.set(p.name, p.type);
      }
      // JETH242/243: a dynamic value-element array / bytes / string param of an @internal/@private
      // function is likewise a MEMORY reference, so `p[i]`/`p.length`/`return p` resolve to memory.
      if (internalOnly && p.type.kind === 'array' && p.type.length === undefined && isStaticValueType(p.type.element)) {
        this.memArrayLocals.add(p.name);
      }
      // a STATIC fixed-array param (Arr<T,N>) is a MEMORY pointer too, so `p[i]` resolves to a
      // memory element (memElem) and `return p` to the image, like a struct param.
      if (internalOnly && p.type.kind === 'array' && p.type.length !== undefined && isStaticType(p.type)) {
        this.memAggregateLocals.set(p.name, p.type);
      }
      if (internalOnly && isBytesLike(p.type)) {
        this.memDynLocals.add(p.name);
      }
      // a DYNAMIC-field struct param of an @internal/@private function is a MEMORY pointer (the
      // pointer-headed image: value fields inline, bytes/string a [len][data] pointer), so `p.x`
      // resolves to a memDynStruct field. Restricted to the shape buildDynStructLocal supports.
      if (internalOnly && this.isSupportedDynStructLocal(p.type)) {
        this.memDynStructLocals.set(p.name, p.type);
      }
    }

    // F3: eagerly type/range-check every constant default, so a bad default (wrong type or out of
    // range for the parameter) is reported at the declaration even when the helper is never called
    // internally (matching TypeScript, which flags type errors in unused code). Defaults are
    // self-contained constants, so snapshot/restore the effect flags to keep this purely diagnostic.
    if (rf.defaults) {
      const rs = this.currentReadsState,
        ws = this.currentWritesState,
        re = this.currentReadsEnv;
      for (let i = 0; i < rf.params.length; i++) {
        const d = rf.defaults[i];
        if (!d) continue;
        const e = this.checkExpr(d, rf.params[i]!.type);
        if (e) this.coerce(e, rf.params[i]!.type, d);
      }
      this.currentReadsState = rs;
      this.currentWritesState = ws;
      this.currentReadsEnv = re;
    }

    const body: Stmt[] = [];
    if (rf.node.body) {
      // The function BODY is a child of the parameter scope, so a body local may shadow a parameter
      // (solc allows this with only a warning). A same-scope redeclaration is still rejected, and the
      // shadow resolves innermost-first (the codegen gives each declaration a unique Yul name).
      this.pushScope();
      for (const s of rf.node.body.statements) {
        this.checkStatement(s, rf.returnType, body);
      }
      this.popScope();
    }

    // Phase 5: inline applied @modifiers around the body. Done while the function PARAMETER scope is
    // still active so a modifier ARGUMENT can reference the function's parameters (its effects also
    // accumulate into this function's effect flags, feeding the purity fixpoint). The modifier BODY
    // is checked in a fresh scope (it sees only its own params + state, not the function's locals).
    // When NO applied modifier has post-code, `wrap.body` is the inlined [pre, body] (pre-only path,
    // modifierWrap undefined); when at least one has post-code, `wrap.body` stays the RAW wrapped body
    // Z (emitted as userfn_<key>) and `wrap.modifierWrap` is the nested pre/post structure the dispatch
    // lowers (see FunctionIR.modifierWrap).
    const wrap =
      rf.modifiers && rf.modifiers.length
        ? this.wrapModifiers(rf, body)
        : { body, modifierWrap: undefined, modifierArgs: undefined };
    this.popScope();

    // Mutability enforcement (directive §2.7 STATICCALL view semantics) is performed AFTER
    // all bodies are checked, against TRANSITIVE effects (see the call-graph fixpoint in
    // analyze()), so a @view/@pure function that violates via an internal callee is caught.

    // The ABI signature uses the SOURCE function name. An @external library function carries a qualified
    // `L.f` name (to namespace its call-graph key) but its real ABI/selector identity is the BARE `f`, so
    // the library's delegatecall dispatcher case + the call site's selector match solc's `f(...)`. An
    // INTERNAL library function keeps its qualified name (its signature is never dispatched and stays
    // distinct across libraries for the contract-level duplicate check; Phase A unchanged).
    const sigName = rf.libraryExternal ? rf.name.slice(rf.libraryName!.length + 1) : rf.name;
    const signature = functionSignature(
      sigName,
      rf.params.map((p) => p.type),
    );
    const selector = functionSelector(signature);
    return {
      name: rf.name,
      key: this.fkey(rf),
      visibility: rf.visibility,
      mutability: rf.mutability,
      params: rf.params,
      returnType: rf.returnType,
      returnTypes: rf.returnTypes,
      signature,
      selector,
      body: wrap.body,
      nonReentrant: rf.nonReentrant,
      modifierWrap: wrap.modifierWrap,
      modifierArgs: wrap.modifierArgs,
      // a function whose modifiers carry post-code is lowered via its synthesized body function
      // userfn_<key> (the dispatch calls it, then runs the post-code + encodes once), so force it.
      internallyCalled: wrap.modifierWrap ? true : undefined,
    };
  }

  /** Phase 5: fold applied @modifiers around the function body. The leftmost decorator is OUTERMOST,
   *  so wrap innermost-first (reverse source order).
   *
   *  PRE-ONLY path (no applied modifier has post-code): the guard runs before the body and never
   *  touches the return values - a multi-value / aggregate-return function is fine. Returns the
   *  inlined [pre, body] (modifierWrap undefined).
   *
   *  POST path (>=1 applied modifier has post-code): a `return` in the body must run the enclosing
   *  post-code before the value is ABI-encoded once. The body is kept RAW and lowered as a synthesized
   *  Yul function (userfn_<key>); modifierWrap is the nested pre/post structure the dispatch lowers,
   *  with a single {kind:'modifierBody'} marker (the userfn call) at its center. */
  /** Does any applied @modifier route this function through the BUFFERED userfn path? True iff at least
   *  one applied modifier has post-placeholder code OR a whole-body (conditional / multi-placeholder /
   *  bare-`return;`) shape - exactly the shapes that need the body emitted as userfn_<key> and the
   *  buffered-return machinery. Used both to choose the wrap path AND, at body-check time, to register
   *  the function's aggregate params as MEMORY references (the userfn takes them by memory pointer). */
  private usesBufferedModifierPath(rf: RawFunction): boolean {
    if (!rf.modifiers || !rf.modifiers.length) return false;
    return rf.modifiers.some((app) => {
      const m = this.modifiersByName.get(app.name);
      return m !== undefined && (m.postStmts.length > 0 || m.bodyStmts !== undefined);
    });
  }

  /** JETH323: can the buffered modifier-dispatch encode this aggregate RETURN type ONCE from the
   *  userfn's memory pointer (emitModifierReturn)? The supported memory-pointer encoders cover a static
   *  struct / static fixed array (the image is the flat blob), a value-element dynamic array (T[]), bytes/
   *  string, and a supported dynamic-field struct. A nested-dynamic-element array (string[], D[], T[][],
   *  Arr<dyn,N>) has no buffered memory-pointer encoder, so it stays gated. A value type is trivially
   *  encodable (not an aggregate). */
  private isBufferedModifierReturnable(t: JethType): boolean {
    if (isBytesLike(t)) return true;
    if (t.kind === 'struct') return isStaticType(t) || this.isSupportedDynStructLocal(t);
    if (t.kind === 'array') {
      if (t.length !== undefined) return isStaticType(t); // Arr<value,N>: flat image
      return isStaticValueType(t.element); // T[] of a value element: encodeMemArrayReturn
    }
    return true; // a value type
  }

  private wrapModifiers(
    rf: RawFunction,
    bodyIR: Stmt[],
  ): { body: Stmt[]; modifierWrap?: Stmt[]; modifierArgs?: Expr[] } {
    const apps = rf.modifiers!;
    // The buffered userfn path is required when a modifier has POST-placeholder code OR a whole-body
    // (conditional / multi-placeholder / return;) shape: both need the body lowered as a synthesized
    // userfn so a value-returning function's `ret` register can zero-init (the skip-body branch).
    const anyBuffered = this.usesBufferedModifierPath(rf);
    if (!anyBuffered) {
      // PRE-ONLY: the guard runs before the body and never touches the return values.
      let inner = bodyIR;
      for (const app of [...apps].reverse()) inner = this.inlineModifier(app, inner);
      return { body: inner };
    }
    // POST path. The buffered-return machinery lives in the DISPATCH case (it calls the synthesized
    // body function userfn_<key>, runs the post-code, then ABI-encodes once); an INTERNAL function has
    // no dispatch case, so its post-code would never run. Gate it cleanly (solc accepts a modifier on
    // an internal function).
    if (rf.visibility !== 'external') {
      this.diags.error(
        rf.node,
        'JETH323',
        `a @modifier with post-placeholder code on a non-@external function is not supported yet (the buffered-return path runs in the external dispatch entry, which an internal function does not have)`,
      );
      return { body: bodyIR };
    }
    // JETH323 LIFTED for FUNCTION shapes: the synthesized body function userfn_<key> is a NORMAL
    // internal function, so it supports aggregate/dynamic PARAMS, a MULTI-VALUE return, and an aggregate
    // RETURN (struct / fixed / value-element dynamic array). The dispatch materializes each decoded param
    // as the userfn expects (a memory pointer for an aggregate), captures the userfn's result(s) into the
    // buffered `ret` var(s), runs the post-code, then ABI-encodes ONCE. A CONSTRUCTOR with post-code stays
    // gated (no userfn body in creation code - handled in inlineModifier).
    //
    // The dispatch encodes the buffered return ONCE from a MEMORY pointer (emitModifierReturn): value
    // types, bytes/string, a static struct/fixed-array, a value-element dynamic array, and a supported
    // dynamic-field struct. Return shapes whose memory-pointer encoder is not wired through the buffered
    // path (a nested-dynamic-element array string[]/D[]/T[][]/Arr<dyn,N>, or a multi-value tuple with an
    // aggregate component) stay gated JETH323 (a clean over-rejection: solc accepts them).
    const aggRet = rf.returnType.kind === 'struct' || rf.returnType.kind === 'array';
    if (aggRet && !this.isBufferedModifierReturnable(rf.returnType)) {
      this.diags.error(
        rf.node,
        'JETH323',
        `a @modifier with post-placeholder code on a function returning ${displayName(rf.returnType)} is not supported yet (the buffered-return path encodes value types, bytes/string, a static struct/fixed-array, a value-element dynamic array, or a supported dynamic struct)`,
      );
      return { body: bodyIR };
    }
    if (rf.returnTypes && rf.returnTypes.some((t) => t.kind === 'struct' || t.kind === 'array')) {
      this.diags.error(
        rf.node,
        'JETH323',
        `a @modifier with post-placeholder code on a multi-value return containing an aggregate component is not supported yet (the buffered-return path encodes value/bytes/string tuple components)`,
      );
      return { body: bodyIR };
    }
    // The {modifierBody} marker calls userfn_<key>(<args>); build one argument Expr per function param
    // (a value-type param echoes as a register, an aggregate/dynamic param echoes as a memory pointer)
    // using the SAME resolution a normal arg pass would, so the dispatch's lowerCallArgs materializes
    // each correctly (JETH323: aggregate params are now supported).
    const modifierArgs = rf.params.map((p) => this.paramRefExpr(p.name, p.type));
    // Build the nested wrap innermost-first: the innermost modifier's `inner` is the placeholder
    // marker (the userfn call); each outer modifier wraps the inner modifier's wrap.
    let inner: Stmt[] = [{ kind: 'modifierBody' }];
    for (const app of [...apps].reverse()) inner = this.buildModifierWrap(app, inner);
    return { body: bodyIR, modifierWrap: inner, modifierArgs };
  }

  /** JETH323: build the argument Expr that echoes a wrapped function's parameter `name` of type `t`
   *  into the synthesized body call userfn_<key>(...). Mirrors the identifier-read resolution in
   *  checkExpr: a value type -> localRead; bytes/string -> dynParamRead; a dynamic array / Arr<dyn,N>
   *  -> a calldataArray echo; a dynamic struct -> cdDynStructValue; a static struct / fixed array ->
   *  cdAggregateValue. The dispatch's lowerCallArgs then passes a value as a register and materializes
   *  an aggregate into the memory pointer the (internal) userfn expects - identical to a normal call. */
  private paramRefExpr(name: string, t: JethType): Expr {
    if (isBytesLike(t)) return { kind: 'dynParamRead', type: t, name };
    if (t.kind === 'array' && (t.length === undefined || isDynamicType(t.element)))
      return { kind: 'arrayValue', type: t, arr: { base: { kind: 'calldataArray', name }, elem: t.element } };
    if (t.kind === 'struct' && isDynamicType(t)) return { kind: 'cdDynStructValue', type: t, param: name };
    if ((t.kind === 'array' || t.kind === 'struct') && isStaticType(t))
      return { kind: 'cdAggregateValue', type: t, param: name };
    return { kind: 'localRead', type: t, name };
  }

  /** Phase 5 (POST path): build one modifier's wrap around `inner` (the inner modifier's wrap, or the
   *  {modifierBody} marker for the innermost). The modifier's params are scoped to the WHOLE block so
   *  they are visible to both pre and post code; pre and post are checked in the SAME fresh modifier
   *  scope (params + state only). Result: [{block: [argDecls, ...pre, ...inner, ...post]}]. Here `inner`
   *  is a CALL marker (not the inlined body), so the param-shadow concern that forces pre-only to keep
   *  the body outside the block does not apply. */
  private buildModifierWrap(app: { name: string; argNodes: ts.Expression[]; site: ts.Node }, inner: Stmt[]): Stmt[] {
    const mod = this.modifiersByName.get(app.name);
    if (!mod) {
      this.diags.error(
        app.site,
        'JETH329',
        `unknown modifier '@${app.name}' (no @modifier with that name is declared)`,
      );
      return inner;
    }
    if (app.argNodes.length !== mod.params.length) {
      this.diags.error(
        app.site,
        'JETH329',
        `modifier '@${mod.name}' expects ${mod.params.length} argument(s), but got ${app.argNodes.length}`,
      );
      return inner;
    }
    // 1. Materialize each arg ONCE (in the function param scope, so a same-named function param is
    //    resolved before the modifier param name is bound) - identical to the pre-only path.
    const argDecls: Stmt[] = [];
    for (let i = 0; i < mod.params.length; i++) {
      const a = this.checkExpr(app.argNodes[i]!, mod.params[i]!.type);
      if (!a) continue;
      const coerced = this.coerce(a, mod.params[i]!.type, app.argNodes[i]!);
      argDecls.push({ kind: 'localDecl', name: mod.params[i]!.name, type: mod.params[i]!.type, init: coerced });
      // An AGGREGATE/DYNAMIC modifier param (JETH322): register it in the memory-local maps so a body
      // read p.length / p[i] / p.x resolves to the materialized memory place (see inlineModifier).
      this.registerAggregateModifierParam(mod.params[i]!.name, mod.params[i]!.type);
    }
    // 2. CONDITIONAL-placeholder shape (`if (c) { _; }` etc.): lower the WHOLE body in a fresh modifier
    //    scope with the single `_;` placeholder replaced IN PLACE by `inner` (the {modifierBody} marker,
    //    intercepted in checkStatement via placeholderInner). The marker lands wherever `_;` sat - even
    //    nested in a conditional/loop - so the wrapped body runs 0-or-N times; a 0-times path leaves the
    //    buffered `ret` at its zero-init = solc's zero value. The result is wrapped in a block so the
    //    modifier's params/locals are scoped to the whole body.
    if (mod.bodyStmts) {
      const savedScopesC = this.scopes;
      this.scopes = [new Map()];
      this.pushScope();
      for (const p of mod.params) this.declareLocal(p.name, p.type);
      const lowered: Stmt[] = [];
      const savedPlaceholder = this.placeholderInner;
      this.placeholderInner = inner;
      for (const s of mod.bodyStmts) this.checkStatement(s, VOID, lowered);
      this.placeholderInner = savedPlaceholder;
      this.popScope();
      this.scopes = savedScopesC;
      return [{ kind: 'block', body: [...argDecls, ...lowered] }];
    }
    // 2. (top-level placeholder) Check pre AND post in the SAME fresh scope (only the modifier's params
    //    + contract state).
    const savedScopes = this.scopes;
    this.scopes = [new Map()];
    this.pushScope();
    for (const p of mod.params) this.declareLocal(p.name, p.type);
    const pre: Stmt[] = [];
    for (const s of mod.preStmts) this.checkStatement(s, VOID, pre);
    const post: Stmt[] = [];
    for (const s of mod.postStmts) this.checkStatement(s, VOID, post);
    this.popScope();
    this.scopes = savedScopes;
    // 3. Wrap [argDecls, pre, inner, post] in a block so the modifier's params are scoped to the whole
    //    wrap (visible to pre AND post). `inner` is a call marker, not the inlined body, so no shadow.
    return [{ kind: 'block', body: [...argDecls, ...pre, ...inner, ...post] }];
  }

  /** Inline one PRE-ONLY modifier application around `inner`: materialize its args (in the function
   *  param scope), then splice [argDecls, pre-code, inner] inside a block (for lexical scoping). The
   *  modifier's pre-code is checked in a FRESH scope so it cannot see the function's params/locals. */
  private inlineModifier(app: { name: string; argNodes: ts.Expression[]; site: ts.Node }, inner: Stmt[]): Stmt[] {
    const mod = this.modifiersByName.get(app.name);
    if (!mod) {
      this.diags.error(
        app.site,
        'JETH329',
        `unknown modifier '@${app.name}' (no @modifier with that name is declared)`,
      );
      return inner;
    }
    if (app.argNodes.length !== mod.params.length) {
      this.diags.error(
        app.site,
        'JETH329',
        `modifier '@${mod.name}' expects ${mod.params.length} argument(s), but got ${app.argNodes.length}`,
      );
      return inner;
    }
    // A modifier with POST-placeholder code reaches this inliner ONLY on a CONSTRUCTOR (a function
    // routes any-post through buildModifierWrap). The constructor body runs in creation code with no
    // synthesized body function, so the buffered-return machinery is unavailable: gate it cleanly. (A
    // ctor rarely early-returns, but inlining [pre, body, post] would drop the post on a `return;` -
    // a miscompile - so we reject rather than risk it.)
    if (mod.postStmts.length > 0) {
      this.diags.error(
        app.site,
        'JETH323',
        `a @modifier with post-placeholder code applied to a constructor is not supported yet (the buffered-return path requires a function body, not creation code)`,
      );
      return inner;
    }
    // A CONDITIONAL-placeholder modifier (the 0-or-N-times shape) likewise reaches this inliner ONLY
    // on a CONSTRUCTOR. Inlining it would need the marker replaced inside the conditional, but the
    // ctor body has no synthesized userfn to call - so gate it cleanly (solc accepts it).
    if (mod.bodyStmts) {
      this.diags.error(
        app.site,
        'JETH323',
        `a @modifier with a conditional '_' placeholder applied to a constructor is not supported yet (the 0-or-N-times path requires a function body, not creation code)`,
      );
      return inner;
    }
    // 1. Materialize each arg ONCE (solc evaluates a modifier arg exactly once) in the function param
    //    scope, bound to the modifier's parameter name. The localDecl init is evaluated before the
    //    name is (re)bound, so an arg referencing a same-named function param resolves correctly.
    const argDecls: Stmt[] = [];
    for (let i = 0; i < mod.params.length; i++) {
      const a = this.checkExpr(app.argNodes[i]!, mod.params[i]!.type);
      if (!a) continue;
      const coerced = this.coerce(a, mod.params[i]!.type, app.argNodes[i]!);
      argDecls.push({ kind: 'localDecl', name: mod.params[i]!.name, type: mod.params[i]!.type, init: coerced });
      // An AGGREGATE/DYNAMIC modifier param (JETH322): the localDecl materializes the arg into a memory
      // local, so register the param name in the memory-local maps (exactly like a function/ctor by-ref
      // param) so a pre-code read p.length / p[i] / p.x resolves to that memory place.
      this.registerAggregateModifierParam(mod.params[i]!.name, mod.params[i]!.type);
    }
    // 2. Check the modifier pre-code in a FRESH scope (only its own params + contract state visible).
    const savedScopes = this.scopes;
    this.scopes = [new Map()];
    this.pushScope();
    for (const p of mod.params) this.declareLocal(p.name, p.type);
    const pre: Stmt[] = [];
    for (const s of mod.preStmts) this.checkStatement(s, VOID, pre);
    this.popScope();
    this.scopes = savedScopes;
    // 3. Wrap ONLY [argDecls, pre-code] in a block so the modifier's params/locals are scoped to the
    //    guard and POPPED before the function body runs. `inner` (the function body) must stay OUTSIDE
    //    the block: otherwise a modifier param sharing a NAME with a function param would shadow it in
    //    codegen's flat name map and the body would read the modifier's value (a silent miscompile).
    //    For pre-only modifiers there is no post-code, so the body simply follows the guard.
    return [{ kind: 'block', body: [...argDecls, ...pre] }, ...inner];
  }

  /** Phase 5: collect a user-defined @modifier. Increment 1 supports a PRE-ONLY modifier: a single
   *  `_;` placeholder in TAIL position (the last statement). The pre-code is the guard that runs
   *  before the wrapped function body; post-placeholder code and a conditional placeholder are gated. */
  private collectModifier(member: ts.MethodDeclaration): void {
    if (!ts.isIdentifier(member.name)) {
      this.diags.error(member, 'JETH049', 'modifier name must be a plain identifier');
      return;
    }
    const name = member.name.text;
    if (this.modifiersByName.has(name)) {
      this.diags.error(member, 'JETH046', `duplicate @modifier '${name}'`);
      return;
    }
    const decs = decoratorNames(member);
    const bad = [
      'external',
      'public',
      'internal',
      'private',
      'view',
      'pure',
      'payable',
      'read',
      'hidden',
      'nonReentrant',
    ].find((d) => decs.includes(d));
    if (bad)
      this.diags.error(
        member,
        'JETH330',
        `a @modifier cannot also be @${bad} (a modifier has no visibility or mutability)`,
      );
    if (member.type) this.diags.error(member.type, 'JETH330', 'a @modifier cannot declare a return type');
    if (member.typeParameters && member.typeParameters.length > 0)
      this.diags.error(member, 'JETH327', 'a generic @modifier is not supported yet');

    const params: { name: string; type: JethType }[] = [];
    for (const p of member.parameters) {
      if (!ts.isIdentifier(p.name)) {
        this.diags.error(p, 'JETH053', 'parameter name must be a plain identifier');
        continue;
      }
      const t = resolveType(p.type, this.diags, this.structsByName);
      if (!t) continue;
      if (p.initializer)
        this.diags.error(p, 'JETH304', `a @modifier parameter ('${p.name.text}') cannot have a default value`);
      // A @modifier parameter may be any type a FUNCTION parameter may be: a value type, bytes/string, a
      // supported array, or a struct of those. The modifier ARG is materialized once in the function's
      // param scope (an aggregate arg into a memory local), exactly like a function call argument. KEEP
      // the mapping reject (storage-only, never passable as an argument) - matches solc + function params.
      if (this.typeHasMapping(t)) {
        this.diags.error(
          p,
          'JETH247',
          `a @modifier parameter ('${p.name.text}') of type ${displayName(t)} contains a mapping and cannot be passed (mappings are storage-only)`,
        );
        continue;
      }
      params.push({ name: p.name.text, type: t });
    }

    if (!member.body) {
      this.diags.error(member, 'JETH328', `a @modifier must have a body containing the placeholder '_'`);
      return;
    }
    const stmts = member.body.statements;
    const placeholders = this.findPlaceholders(member.body);
    if (placeholders.length === 0) {
      this.diags.error(member, 'JETH328', `a @modifier body must contain the placeholder '_' exactly once`);
      return;
    }
    // A `return expr;` is meaningless (a modifier has no return type) - solc rejects it too (JETH324,
    // kept). A bare `return;` is ALLOWED (JETH325 lifted): it early-exits the wrapped function with the
    // CURRENT return values (the buffered `ret` register, zero-init or whatever the body/modifier set so
    // far), byte-identical to solc. A modifier with a `return;` therefore needs the whole-body buffered
    // path (the `return;` lowers to the dispatch's encode-once of the buffered `ret`), so it routes
    // through bodyStmts below regardless of placeholder position.
    const returns = this.findReturns([...stmts]);
    let hasBareReturn = false;
    let hasValueReturn = false;
    for (const r of returns) {
      if (r.expression) {
        this.diags.error(r, 'JETH324', `a @modifier cannot 'return' a value`);
        hasValueReturn = true;
      } else hasBareReturn = true;
    }
    if (hasValueReturn) return; // don't register a modifier with a value-return (avoids a cascade on inlining)
    // Shape selection. The flat pre/post FAST path is used ONLY for the canonical shape: EXACTLY ONE
    // placeholder, at TOP LEVEL of the body, with NO `return;`. Every other shape (multiple placeholders,
    // a nested/conditional placeholder, or a bare `return;`) routes through the WHOLE-BODY buffered path:
    // the body is stored (bodyStmts) and later lowered with EACH `_;` replaced IN PLACE by the
    // {modifierBody} marker (the userfn call) - so the body runs once per placeholder (N placeholders =>
    // N calls, `ret` holds the last call's value) and a `return;` early-out leaves `ret` at its current
    // value. A 0-times conditional path leaves the buffered `ret` at its zero-init = solc's zero value.
    const topIdx = stmts.findIndex((s) => this.isPlaceholderStmt(s));
    const useFlat = placeholders.length === 1 && topIdx >= 0 && !hasBareReturn;
    const preStmts = useFlat ? stmts.slice(0, topIdx) : [];
    const postStmts = useFlat ? stmts.slice(topIdx + 1) : [];
    this.modifiersByName.set(name, {
      name,
      node: member,
      params,
      preStmts,
      postStmts,
      bodyStmts: useFlat ? undefined : [...stmts],
    });
  }

  private isPlaceholderStmt(s: ts.Statement): boolean {
    return ts.isExpressionStatement(s) && ts.isIdentifier(s.expression) && s.expression.text === '_';
  }
  /** Find every `_;` placeholder ExpressionStatement anywhere in a node (recursively). */
  private findPlaceholders(node: ts.Node): ts.Node[] {
    const out: ts.Node[] = [];
    const walk = (n: ts.Node) => {
      if (ts.isExpressionStatement(n) && ts.isIdentifier(n.expression) && n.expression.text === '_') out.push(n);
      ts.forEachChild(n, walk);
    };
    ts.forEachChild(node, walk);
    return out;
  }
  private findReturns(stmts: ts.Statement[]): ts.ReturnStatement[] {
    const out: ts.ReturnStatement[] = [];
    const walk = (n: ts.Node) => {
      if (ts.isReturnStatement(n)) out.push(n);
      ts.forEachChild(n, walk);
    };
    for (const s of stmts) walk(s);
    return out;
  }

  // ---- statements ----------------------------------------------------------

  private checkStatement(node: ts.Statement, returnType: JethType, out: Stmt[]): void {
    if (ts.isReturnStatement(node)) {
      // multi-value return: `return [a, b, ...]` matching the function's tuple return type.
      if (this.currentReturnTypes) {
        const rts = this.currentReturnTypes;
        // `return mk(args)` / `return this.mk(args)`: forward a tuple-returning INTERNAL call
        // directly (solc accepts this). Desugar to `let [t0..tk] = mk(args); return [t0,..,tk]`,
        // reusing the tested tuple-destructure (call source) + multi-return lowering. The synthetic
        // locals are registered in the same side-tables checkTupleDecl uses, so the returnTuple
        // component reads resolve through the right codec per component kind.
        const tcName = node.expression ? this.tupleCallName(node.expression) : undefined;
        if (tcName) {
          const r = this.resolveTupleCall(node.expression as ts.CallExpression, tcName, rts.length);
          if (!r) return;
          for (let i = 0; i < rts.length; i++) {
            if (!typesEqual(r.types[i]!, rts[i]!) && !isImplicitWiden(r.types[i]!, rts[i]!)) {
              this.diags.error(
                node.expression!,
                'JETH060',
                `returned tuple component ${i} is ${displayName(r.types[i]!)}, expected ${displayName(rts[i]!)}`,
              );
              return;
            }
          }
          const names: string[] = [];
          for (let i = 0; i < rts.length; i++) {
            const nm = this.freshSynthName('__jeth_tret_');
            this.declareLocal(nm, r.types[i]!);
            const ct = r.types[i]!;
            if (isBytesLike(ct)) this.memDynLocals.add(nm);
            else if (ct.kind === 'array' && ct.length === undefined && isStaticValueType(ct.element))
              this.memArrayLocals.add(nm);
            else if (ct.kind === 'struct') this.memAggregateLocals.set(nm, ct);
            names.push(nm);
          }
          out.push({ kind: 'tupleDecl', names, types: r.types, source: { kind: 'call', fn: r.fn, args: r.args } });
          const fwd: Expr[] = names.map((nm, i) => {
            const ct = r.types[i]!;
            let read: Expr;
            if (isBytesLike(ct)) read = { kind: 'dynLocalRead', type: ct, name: nm };
            else if (ct.kind === 'array' && ct.length === undefined && isStaticValueType(ct.element))
              read = {
                kind: 'arrayValue',
                type: ct,
                arr: { base: { kind: 'memArray', varName: nm }, elem: ct.element },
              };
            else if (ct.kind === 'struct') read = { kind: 'memAggregate', type: ct, local: nm };
            else read = { kind: 'localRead', type: ct, name: nm };
            return this.coerce(read, rts[i]!, node.expression!);
          });
          out.push({ kind: 'returnTuple', values: fwd, types: rts });
          return;
        }
        if (!node.expression || !ts.isArrayLiteralExpression(node.expression)) {
          this.diags.error(
            node,
            'JETH060',
            `function must return a ${rts.length}-tuple [${rts.map(displayName).join(', ')}]`,
          );
          return;
        }
        if (node.expression.elements.length !== rts.length) {
          this.diags.error(
            node,
            'JETH060',
            `return tuple has ${node.expression.elements.length} values, expected ${rts.length}`,
          );
          return;
        }
        const values: Expr[] = [];
        for (let i = 0; i < rts.length; i++) {
          const v = this.checkExpr(node.expression.elements[i]!, rts[i]);
          if (!v) return;
          const cv = this.coerce(v, rts[i]!, node.expression.elements[i]!);
          // An aggregate component may be a STORAGE value (this.x / this.m[k] / this.arr[i]), a
          // MEMORY value-array, or a whole DYNAMIC calldata param (a calldata array / dynamic
          // struct), echoed via the recursive calldata encoder. A calldata array ELEMENT
          // (cdNestedElem) or a static calldata aggregate component is still a later step.
          if (rts[i]!.kind === 'struct' || rts[i]!.kind === 'array') {
            // A whole calldata PARAM component is supported: a dynamic array / dynamic struct (offset
            // word + tail), or a STATIC fixed-array / struct (inline head). A calldata array ELEMENT
            // (cdNestedElem) is still a later step.
            const cdParamOk =
              (cv.kind === 'arrayValue' && cv.arr.base.kind === 'calldataArray') ||
              cv.kind === 'cdDynStructValue' ||
              cv.kind === 'cdAggregateValue';
            if (this.isCalldataAggregate(cv) && !cdParamOk) {
              this.diags.error(
                node.expression.elements[i]!,
                'JETH213',
                'this calldata-aggregate component in a multi-value return is not supported yet (a whole calldata array/struct param works; a calldata array ELEMENT does not)',
              );
              return;
            }
          }
          values.push(cv);
        }
        out.push({ kind: 'returnTuple', values, types: rts });
        return;
      }
      if (!node.expression) {
        if (returnType.kind !== 'void') {
          this.diags.error(node, 'JETH060', `function must return ${displayName(returnType)}`);
        }
        out.push({ kind: 'return' });
        return;
      }
      const value = this.checkExpr(node.expression, returnType);
      if (value) {
        const coerced = this.coerce(value, returnType, node.expression);
        out.push({ kind: 'return', value: coerced });
      }
      return;
    }

    if (ts.isVariableStatement(node)) {
      for (const decl of node.declarationList.declarations) {
        this.checkLocalDecl(decl, out);
      }
      return;
    }

    if (ts.isTryStatement(node)) {
      this.checkTryStatement(node, returnType, out);
      return;
    }

    // bare block `{ ... }` introduces a lexical scope
    if (ts.isBlock(node)) {
      this.pushScope();
      const body: Stmt[] = [];
      for (const s of node.statements) this.checkStatement(s, returnType, body);
      this.popScope();
      out.push({ kind: 'block', body });
      return;
    }

    // `unchecked: { ... }` (a labeled block) is Solidity's `unchecked { }`: arithmetic
    // (+ - * ** unary-) wraps mod 2^bits instead of reverting on overflow. The TS subset
    // has no `unchecked` keyword, so the labeled-block form carries the annotation.
    if (ts.isLabeledStatement(node) && node.label.text === 'unchecked' && ts.isBlock(node.statement)) {
      const prev = this.currentUnchecked;
      // solc forbids nesting `unchecked` blocks ("\"unchecked\" blocks cannot be nested").
      if (prev) this.diags.error(node, 'JETH288', '`unchecked` blocks cannot be nested');
      this.currentUnchecked = true;
      this.pushScope();
      const body: Stmt[] = [];
      for (const s of node.statement.statements) this.checkStatement(s, returnType, body);
      this.popScope();
      this.currentUnchecked = prev;
      out.push({ kind: 'block', body });
      return;
    }

    if (ts.isIfStatement(node)) {
      const cond = this.checkCondition(node.expression);
      const thenB = this.checkBranch(node.thenStatement, returnType);
      const elseB = node.elseStatement ? this.checkBranch(node.elseStatement, returnType) : undefined;
      if (cond) out.push({ kind: 'if', cond, then: thenB, else: elseB });
      return;
    }

    if (ts.isSwitchStatement(node)) {
      this.checkSwitchStatement(node, returnType, out);
      return;
    }

    if (ts.isWhileStatement(node)) {
      const cond = this.checkCondition(node.expression);
      this.loopDepth++;
      const body = this.checkBranch(node.statement, returnType);
      this.loopDepth--;
      if (cond) out.push({ kind: 'while', cond, body });
      return;
    }

    if (ts.isDoStatement(node)) {
      // do { body } while (cond): body runs once, then cond is re-checked each turn.
      // The condition lives in the enclosing scope (body-declared locals are NOT visible
      // to it - checkBranch gives the body its own scope, matching Solidity/C semantics).
      this.loopDepth++;
      const body = this.checkBranch(node.statement, returnType);
      this.loopDepth--;
      const cond = this.checkCondition(node.expression);
      if (cond) out.push({ kind: 'doWhile', cond, body });
      return;
    }

    if (ts.isForStatement(node)) {
      this.checkForStatement(node, returnType, out);
      return;
    }

    if (ts.isForOfStatement(node)) {
      this.checkForOfStatement(node, returnType, out);
      return;
    }
    if (ts.isForInStatement(node)) {
      this.diags.error(node, 'JETH111', 'for-in loops are not supported; iterate an array with for-of');
      return;
    }

    if (node.kind === ts.SyntaxKind.BreakStatement) {
      if ((node as ts.BreakStatement).label) this.diags.error(node, 'JETH112', 'labeled break is not supported');
      else if (this.loopDepth === 0) this.diags.error(node, 'JETH113', "'break' outside of a loop");
      else out.push({ kind: 'break' });
      return;
    }
    if (node.kind === ts.SyntaxKind.ContinueStatement) {
      if ((node as ts.ContinueStatement).label) this.diags.error(node, 'JETH112', 'labeled continue is not supported');
      else if (this.loopDepth === 0) this.diags.error(node, 'JETH113', "'continue' outside of a loop");
      else out.push({ kind: 'continue' });
      return;
    }

    if (ts.isExpressionStatement(node)) {
      const e = node.expression;
      // The `_;` placeholder of a CONDITIONAL-placeholder modifier body: splice the {modifierBody}
      // marker (the wrapped-body call) in place. Active ONLY while buildModifierWrap lowers such a
      // body (placeholderInner set); at any other site `_` is an ordinary (and unknown) identifier.
      if (this.placeholderInner && ts.isIdentifier(e) && e.text === '_') {
        out.push(...this.placeholderInner);
        return;
      }
      // built-in statement-only calls: require / revert / emit
      if (ts.isCallExpression(e) && ts.isIdentifier(e.expression)) {
        const callee = e.expression.text;
        if (callee === 'require') return this.checkRequire(e, out);
        if (callee === 'assert') return this.checkAssert(e, out);
        if (callee === 'revert') return this.checkRevert(e, out);
        if (callee === 'revertWith') return this.checkRevertWith(e, out);
        if (callee === 'emit') return this.checkEmit(e, out);
        // a bare internal call as a statement (void result, or a value result discarded).
        if (this.funcsByName.has(callee)) {
          const c = this.checkInternalCall(e, callee, true);
          if (c) out.push({ kind: 'callStmt', fn: c.fn, args: c.args });
          return;
        }
        // F6: a generic internal call `f<T>(...)` / `f(...)` as a statement.
        if (this.genericsByName.has(callee)) {
          const c = this.checkGenericCall(e, callee, true);
          if (c) out.push({ kind: 'callStmt', fn: c.fn, args: c.args });
          return;
        }
      }
      // `super.method(args)` as a statement -> resolve up the linearization (inheritance).
      if (
        ts.isCallExpression(e) &&
        ts.isPropertyAccessExpression(e.expression) &&
        e.expression.expression.kind === ts.SyntaxKind.SuperKeyword
      ) {
        const c = this.checkSuperCall(e, e.expression.name.text, true);
        if (c) out.push({ kind: 'callStmt', fn: c.fn, args: c.args });
        return;
      }
      // `this.method(args)` internal call as a statement (TS-idiomatic).
      if (
        ts.isCallExpression(e) &&
        ts.isPropertyAccessExpression(e.expression) &&
        e.expression.expression.kind === ts.SyntaxKind.ThisKeyword &&
        this.funcsByName.has(e.expression.name.text)
      ) {
        const c = this.checkInternalCall(e, e.expression.name.text, true);
        if (c) out.push({ kind: 'callStmt', fn: c.fn, args: c.args });
        return;
      }
      // F6: `this.f<T>(args)` generic internal call as a statement.
      if (
        ts.isCallExpression(e) &&
        ts.isPropertyAccessExpression(e.expression) &&
        e.expression.expression.kind === ts.SyntaxKind.ThisKeyword &&
        this.genericsByName.has(e.expression.name.text)
      ) {
        const c = this.checkGenericCall(e, e.expression.name.text, true);
        if (c) out.push({ kind: 'callStmt', fn: c.fn, args: c.args });
        return;
      }
      // Phase A: qualified library call as a statement `L.f(args);` (void result or value discarded).
      if (
        ts.isCallExpression(e) &&
        ts.isPropertyAccessExpression(e.expression) &&
        ts.isIdentifier(e.expression.expression) &&
        this.isLibraryName(e.expression.expression.text) &&
        !this.isVisibleLocal(e.expression.expression.text) &&
        !this.stateByName.has(e.expression.expression.text)
      ) {
        const c = this.resolveQualifiedLibraryCall(e, e.expression.expression.text, e.expression.name.text, true);
        if (c)
          out.push(c.kind === 'call' ? { kind: 'callStmt', fn: c.fn, args: c.args } : { kind: 'exprStmt', expr: c });
        return;
      }
      // Phase 6: a high-level typed interface call as a statement `IFoo(addr).method(args);`. The call
      // (selector ++ args, bubble + extcodesize guard) runs; the returndata is captured but discarded
      // (no decode, even for a value-returning method). Performed before the array-mutator / fall-through
      // handling so the wrapper's `IFoo(addr).method` PropertyAccess is recognized first.
      {
        const ic = this.resolveInterfaceCall(e);
        if (ic === 'handled') return;
        if (ic) {
          out.push({ kind: 'exprStmt', expr: ic.call });
          return;
        }
      }
      // A same-name collision between an @using attached fn and a BUILT-IN member of the SAME
      // receiver type is ambiguous in solc (rejected). Check BEFORE the built-in handlers (push/pop)
      // so the built-in cannot silently win. A lib fn attached to a DIFFERENT type is not a collision.
      if (
        ts.isCallExpression(e) &&
        ts.isPropertyAccessExpression(e.expression) &&
        this.libraryAttachments.size > 0 &&
        !(e.expression.expression.kind === ts.SyntaxKind.ThisKeyword) &&
        !(e.expression.expression.kind === ts.SyntaxKind.SuperKeyword)
      ) {
        const recvType = this.trialExprType(e.expression.expression);
        if (recvType && this.attachedBuiltinCollision(e, e.expression.expression, recvType, e.expression.name.text))
          return;
      }
      // array mutators: a.push(x) / a.pop()
      if (ts.isCallExpression(e) && ts.isPropertyAccessExpression(e.expression)) {
        const method = e.expression.name.text;
        if (method === 'push' || method === 'pop') return this.checkArrayMutator(e, method, out);
      }
      // x++ / x-- / ++x / --x as a statement: desugar to x = x +/- 1 (checked / unchecked).
      if (ts.isPostfixUnaryExpression(e)) {
        return this.checkIncDec(e.operand, e.operator === ts.SyntaxKind.PlusPlusToken, e, out);
      }
      if (
        ts.isPrefixUnaryExpression(e) &&
        (e.operator === ts.SyntaxKind.PlusPlusToken || e.operator === ts.SyntaxKind.MinusMinusToken)
      ) {
        return this.checkIncDec(e.operand, e.operator === ts.SyntaxKind.PlusPlusToken, e, out);
      }
      // `delete x` statement: reset a storage location to its zero value.
      if (ts.isDeleteExpression(e)) {
        return this.checkDelete(e, out);
      }
      // Phase A: an attached library method as a statement `x.f(args);` == `L.f(x, ...args);`.
      // Placed AFTER the built-in statement handlers (this.f / interface call / push|pop / inc-dec /
      // delete) so a built-in always wins; only fires when x's type has a (T, f) @using attachment.
      if (
        ts.isCallExpression(e) &&
        ts.isPropertyAccessExpression(e.expression) &&
        this.libraryAttachments.size > 0 &&
        !(e.expression.expression.kind === ts.SyntaxKind.ThisKeyword) &&
        !(e.expression.expression.kind === ts.SyntaxKind.SuperKeyword)
      ) {
        const recvType = this.trialExprType(e.expression.expression);
        if (recvType) {
          const r = this.resolveAttachedLibraryCall(e, e.expression.expression, recvType, e.expression.name.text, true);
          if (r !== 'no-match') {
            if (r)
              out.push(
                r.kind === 'call' ? { kind: 'callStmt', fn: r.fn, args: r.args } : { kind: 'exprStmt', expr: r },
              );
            return;
          }
        }
      }
      this.checkExpressionStatement(e, out);
      return;
    }

    if (ts.isEmptyStatement(node)) {
      // solc's grammar has no empty-statement production: a lone `;` is a parse error. Match it.
      this.diags.error(node, 'JETH061', 'an empty statement `;` is not allowed (remove it)');
      return;
    }

    this.diags.error(node, 'JETH061', `unsupported statement: ${ts.SyntaxKind[node.kind]}`);
  }

  /** Feature 2: `try { let r = IFoo(addr).m(args); <body> } catch (e) { <catch> }`. The try block's
   *  FIRST statement is the controlling high-level interface call; the rest of the try block is the
   *  success body (the bound vars in scope). The catch binds `e: bytes` (the verbatim revert returndata)
   *  and, inside its body only, the scoped helpers `this.reason` (decoded Error(string), soft) and
   *  `this.panic` (decoded Panic code, soft). solc control flow: a failed call -> catch; a non-contract
   *  target / short returndata -> OUTER revert empty (NOT catch). */
  private checkTryStatement(node: ts.TryStatement, returnType: JethType, out: Stmt[]): void {
    if (node.finallyBlock) {
      this.diags.error(node, 'JETH360', 'a `finally` clause is not supported on try/catch');
      return;
    }
    if (!node.catchClause) {
      this.diags.error(node, 'JETH360', 'try requires a catch clause (try/catch around an interface call)');
      return;
    }
    const tryStmts = node.tryBlock.statements;
    if (tryStmts.length === 0) {
      this.diags.error(
        node.tryBlock,
        'JETH361',
        'the try block must begin with the controlling interface call (e.g. `let r = IFoo(addr).m(...)`)',
      );
      return;
    }
    const first = tryStmts[0]!;

    // ---- extract the controlling interface call from the first statement ----
    // Allowed shapes: `let r[:T] = IFoo(addr).m(args);` (single value), `let [a,b]:[..] = IFoo(addr).p();`
    // (tuple), or a bare `IFoo(addr).m(args);` (void / discarded-return) expression statement.
    let call: (Expr & { kind: 'extCall' }) | undefined;
    let retTypes: JethType[] = [];
    let retNames: (string | null)[] = [];
    // names/types to declare in the success-body scope (parallel arrays of the bound vars)
    const succVars: { name: string; type: JethType }[] = [];

    if (ts.isVariableStatement(first)) {
      if (first.declarationList.declarations.length !== 1) {
        this.diags.error(
          first,
          'JETH361',
          'the controlling try statement must declare exactly one binding from the interface call',
        );
        return;
      }
      const decl = first.declarationList.declarations[0]!;
      if (!decl.initializer) {
        this.diags.error(
          decl,
          'JETH361',
          'the controlling try statement must initialize from an interface call (`= IFoo(addr).m(...)`)',
        );
        return;
      }
      const ic = this.resolveInterfaceCall(decl.initializer);
      if (ic === 'handled') return; // recognized but diagnosed
      if (!ic) {
        this.diags.error(
          decl.initializer,
          'JETH361',
          'the first statement in a try block must be a high-level interface call `IFoo(addr).m(...)`',
        );
        return;
      }
      call = ic.call;
      if (ts.isArrayBindingPattern(decl.name)) {
        // tuple binding: `let [a, , c]: [T0, T1, T2] = IFoo(addr).pair();`
        if (!ic.returnTypes) {
          this.diags.error(
            decl.name,
            'JETH356',
            ic.returnType.kind === 'void'
              ? 'this interface method returns void and cannot be destructured (call it without a binding)'
              : 'this interface method returns a single value; bind it with `let x = ...`, not a destructuring',
          );
          return;
        }
        const rts = ic.returnTypes;
        const pat = decl.name;
        if (pat.elements.length !== rts.length) {
          this.diags.error(
            decl.name,
            'JETH356',
            `this interface method returns ${rts.length} value(s), expected ${pat.elements.length} name(s)`,
          );
          return;
        }
        // optional `: [T0, T1, ...]` annotation must match the method's return types
        if (decl.type) {
          const ann = this.tupleTypeAnnotation(decl.type, rts.length);
          if (ann)
            for (let i = 0; i < rts.length; i++) {
              if (!typesEqual(ann[i]!, rts[i]!)) {
                this.diags.error(
                  decl.type,
                  'JETH085',
                  `try return type component ${i} is ${displayName(ann[i]!)}, expected ${displayName(rts[i]!)}`,
                );
                return;
              }
            }
        }
        retTypes = rts;
        for (let i = 0; i < rts.length; i++) {
          const el = pat.elements[i]!;
          if (ts.isOmittedExpression(el)) {
            retNames.push(null);
            continue;
          }
          if (!ts.isBindingElement(el) || !ts.isIdentifier(el.name)) {
            this.diags.error(el, 'JETH062', 'only simple names are allowed in a try tuple binding');
            return;
          }
          retNames.push(el.name.text);
          succVars.push({ name: el.name.text, type: rts[i]! });
        }
      } else if (ts.isIdentifier(decl.name)) {
        // single-value binding: `let r: T = IFoo(addr).m(args);`
        if (ic.returnTypes) {
          this.diags.error(
            decl.name,
            'JETH356',
            'this interface method returns a tuple; bind it with a destructuring `let [a, b] = IFoo(addr).m(...)`',
          );
          return;
        }
        if (ic.returnType.kind === 'void') {
          this.diags.error(
            decl.name,
            'JETH357',
            'this interface method returns void and cannot be bound to a name (call it without a binding: `IFoo(addr).m(...);`)',
          );
          return;
        }
        if (decl.type) {
          const ann = resolveType(decl.type, this.diags, this.structsByName);
          if (ann && !typesEqual(ann, ic.returnType)) {
            this.diags.error(
              decl.type,
              'JETH085',
              `try return type is ${displayName(ann)}, but the method returns ${displayName(ic.returnType)}`,
            );
            return;
          }
        }
        retTypes = [ic.returnType];
        retNames = [decl.name.text];
        succVars.push({ name: decl.name.text, type: ic.returnType });
      } else {
        this.diags.error(decl, 'JETH062', 'destructuring is not supported in a try binding');
        return;
      }
    } else if (ts.isExpressionStatement(first)) {
      const ic = this.resolveInterfaceCall(first.expression);
      if (ic === 'handled') return;
      if (!ic) {
        this.diags.error(
          first.expression,
          'JETH361',
          'the first statement in a try block must be a high-level interface call `IFoo(addr).m(...)`',
        );
        return;
      }
      call = ic.call;
      // a bare call statement discards any return value (matches solc's `try ... { } catch`).
      retTypes = [];
      retNames = [];
    } else {
      this.diags.error(
        first,
        'JETH361',
        'the first statement in a try block must be the controlling interface call `let r = IFoo(addr).m(...)` or `IFoo(addr).m(...);`',
      );
      return;
    }

    // ---- success body: the rest of the try block, with the bound vars in scope ----
    this.pushScope();
    const savedMA = new Set(this.memArrayLocals);
    const savedAgg = new Map(this.memAggregateLocals);
    const savedDyn = new Set(this.memDynLocals);
    const savedDynS = new Map(this.memDynStructLocals);
    for (const v of succVars) {
      this.declareLocal(v.name, v.type);
      const ct = v.type;
      if (isBytesLike(ct)) this.memDynLocals.add(v.name);
      else if (ct.kind === 'array' && ct.length === undefined && isStaticValueType(ct.element))
        this.memArrayLocals.add(v.name);
      else if (ct.kind === 'array' && ct.length !== undefined) this.memAggregateLocals.set(v.name, ct);
      else if (ct.kind === 'struct' && isDynamicType(ct)) this.memDynStructLocals.set(v.name, ct);
      else if (ct.kind === 'struct') this.memAggregateLocals.set(v.name, ct);
    }
    const tryBody: Stmt[] = [];
    for (let i = 1; i < tryStmts.length; i++) this.checkStatement(tryStmts[i]!, returnType, tryBody);
    this.popScope();
    // restore mem side-tables (the success vars only existed in the try-body scope)
    this.memArrayLocals = savedMA;
    this.memAggregateLocals = savedAgg;
    this.memDynLocals = savedDyn;
    this.memDynStructLocals = savedDynS;

    // ---- catch body: bind `e: bytes` (if present + named) + scoped this.reason / this.panic ----
    const cc = node.catchClause;
    let catchName: string | null = null;
    if (cc.variableDeclaration) {
      const vd = cc.variableDeclaration;
      if (!ts.isIdentifier(vd.name)) {
        this.diags.error(vd, 'JETH062', 'the catch binding must be a simple name `catch (e) { ... }`');
        return;
      }
      // solc's `catch (bytes memory e)`: the binding is always the raw revert returndata (bytes).
      if (vd.type) {
        const t = resolveType(vd.type, this.diags, this.structsByName);
        if (t && !isBytesLike(t)) {
          this.diags.error(
            vd.type,
            'JETH362',
            `the catch binding is the raw revert returndata and must be \`bytes\`, got ${displayName(t)}`,
          );
          return;
        }
      }
      catchName = vd.name.text;
    }
    this.pushScope();
    const savedMA2 = new Set(this.memArrayLocals);
    const savedDyn2 = new Set(this.memDynLocals);
    if (catchName) {
      this.declareLocal(catchName, BYTES);
      this.memDynLocals.add(catchName); // `e` is a memory bytes local (its register is the [len][data] ptr)
    }
    const savedCatch = this.catchBindings;
    const savedUR = this.catchUsesReason;
    const savedUP = this.catchUsesPanic;
    this.catchBindings = new Map<string, JethType>([
      ['reason', STRING],
      ['panic', U256],
    ]);
    this.catchUsesReason = false;
    this.catchUsesPanic = false;
    const catchBody: Stmt[] = [];
    for (const s of cc.block.statements) this.checkStatement(s, returnType, catchBody);
    const usesReason = this.catchUsesReason;
    const usesPanic = this.catchUsesPanic;
    this.catchBindings = savedCatch;
    this.catchUsesReason = savedUR;
    this.catchUsesPanic = savedUP;
    this.popScope();
    this.memArrayLocals = savedMA2;
    this.memDynLocals = savedDyn2;

    if (!call) return; // a diagnostic already fired
    // the controlling call must NOT auto-bubble (failure -> catch) and the codeGuard is emitted inside the
    // ok-branch by the backend; clear both flags resolveInterfaceCall set for the plain high-level call.
    call.bubble = false;
    call.codeGuard = false;
    out.push({ kind: 'tryCatch', call, retTypes, retNames, tryBody, catchName, usesReason, usesPanic, catchBody });
  }

  /** Parse an explicit tuple-type annotation `[T0, T1, ...]` into N component types, or undefined if it
   *  is not a tuple of the expected arity (callers then skip the match check). */
  private tupleTypeAnnotation(typeNode: ts.TypeNode, n: number): JethType[] | undefined {
    if (!ts.isTupleTypeNode(typeNode) || typeNode.elements.length !== n) return undefined;
    const out: JethType[] = [];
    for (const el of typeNode.elements) {
      const t = resolveType(el, this.diags, this.structsByName);
      if (!t) return undefined;
      out.push(t);
    }
    return out;
  }

  /** `delete x`: reset a storage location to its zero value (Solidity semantics). A VALUE
   *  target lowers to `x = 0` (reusing the packed / array-element / place store paths); a
   *  bytes/string, struct, or array target lowers to a footprint-clearing deleteStmt; a whole
   *  mapping is a no-op (solc leaves mappings untouched). Memory-aggregate deletes are gated. */
  private checkDelete(node: ts.DeleteExpression, out: Stmt[]): void {
    const lv = this.checkLValue(node.expression);
    if (!lv) return;
    const t = lv.type;
    // solc rejects `delete <mapping>` (a whole mapping cannot be cleared; keys are unknown).
    if (t.kind === 'mapping') {
      this.diags.error(node, 'JETH031', "'delete' cannot be applied to a mapping");
      return;
    }
    // a value field/element of a memory aggregate local: reset in place via `= 0`.
    if (lv.kind === 'memField' || lv.kind === 'memElem') {
      if (!isStaticValueType(t)) {
        this.diags.error(node, 'JETH200', `delete of a ${displayName(t)} memory location is not supported yet`);
        return;
      }
      out.push({ kind: 'assign', target: lv, value: { kind: 'literalInt', type: t, value: 0n } });
      return;
    }
    // a value target (storage var / place / mapping value / array element / local): `= 0`.
    if (isStaticValueType(t)) {
      out.push({ kind: 'assign', target: lv, value: { kind: 'literalInt', type: t, value: 0n } });
      return;
    }
    // a whole MEMORY aggregate local (static struct / fixed array): delete rebinds it to a FRESH
    // zeroed instance (solc parity: an alias `b = a` keeps the old value after `delete a`). A bytes/
    // string / dynamic-array / dynamic-struct memory local is deferred.
    if (lv.kind === 'local') {
      if (isStaticType(t) && (t.kind === 'struct' || (t.kind === 'array' && t.length !== undefined))) {
        out.push({ kind: 'deleteStmt', target: lv });
        return;
      }
      // a bytes/string or DYNAMIC-array memory local: delete rebinds it to a fresh empty image
      // (length-0 block: one zeroed word). `.length` reads mload(ptr)==0, matching solc, and an
      // alias keeps the old value. Dynamic structs / fixed arrays with dynamic elements stay gated
      // (their memory head is pointers, not a length-prefixed block, so a 1-word rebind would not
      // reproduce solc's per-member empty reset).
      if (isBytesLike(t) || (t.kind === 'array' && t.length === undefined)) {
        out.push({ kind: 'deleteStmt', target: lv });
        return;
      }
      this.diags.error(node, 'JETH200', `delete of a ${displayName(t)} memory local is not supported yet`);
      return;
    }
    // bytes/string, struct, array, or whole mapping: clear the storage footprint (mapping = no-op).
    out.push({ kind: 'deleteStmt', target: lv });
  }

  /** Assignment / compound-assignment / bare expression statement. */
  private checkExpressionStatement(e: ts.Expression, out: Stmt[]): void {
    if (ts.isBinaryExpression(e) && this.isAssignmentOperator(e.operatorToken.kind)) {
      this.checkAssignment(e, out);
      return;
    }
    const expr = this.checkExpr(e);
    if (expr) out.push({ kind: 'exprStmt', expr });
  }

  private checkStructConstruct(node: ts.CallExpression, st: JethType & { kind: 'struct' }): Expr | undefined {
    // A struct that (transitively) contains a mapping is storage-only and cannot be
    // constructed in memory (matches solc).
    if (this.typeHasMapping(st)) {
      this.diags.error(
        node,
        'JETH247',
        `struct '${st.name}' contains a mapping and cannot be constructed (mappings are storage-only)`,
      );
      return undefined;
    }
    if (node.arguments.length !== st.fields.length) {
      this.diags.error(
        node,
        'JETH228',
        `struct '${st.name}' expects ${st.fields.length} field arg(s), got ${node.arguments.length}`,
      );
      return undefined;
    }
    const args: Expr[] = [];
    for (let i = 0; i < st.fields.length; i++) {
      const a = this.buildStructFieldArg(st.fields[i]!, node.arguments[i]!);
      if (!a) return undefined;
      args.push(a);
    }
    return { kind: 'structNew', type: st, fields: st.fields, args };
  }

  /** Build + validate ONE struct-construction field argument from its AST node, matching solc's
   *  per-field contract. Shared by positional StructName(...) and object-literal {field: val}:
   *  a nested struct must be an inline constructor (so codegen can flatten it); bytes/string a
   *  dynamic value; a static fixed-array an array literal of exactly N; a dynamic value-array any
   *  array source; a value type a value. */
  private buildStructFieldArg(f: StructField, argNode: ts.Expression): Expr | undefined {
    if (f.type.kind === 'struct') {
      const a = this.checkExpr(argNode, f.type);
      if (!a) return undefined;
      const sameStruct = a.type.kind === 'struct' && a.type.name === f.type.name;
      if (a.kind === 'structNew') return a; // an inline constructor
      // a non-inline value of the same struct type. A STATIC field is copied leaf-by-leaf by codegen
      // (R1). A DYNAMIC field from a SIDE-EFFECT-FREE source is desugared into an inline constructor
      // that reads each of the source's fields - StructName(src.f0, src.f1, ...) - which reuses the
      // verified inline encoder and is byte-identical to solc's field-by-field copy.
      if (sameStruct && isStaticType(f.type)) return a;
      if (sameStruct && this.isPureReadExpr(argNode)) return this.desugarStructCopy(f.type, argNode);
      this.diags.error(
        argNode,
        'JETH226',
        sameStruct
          ? `dynamic struct field '${f.name}' must be constructed inline or come from a simple (side-effect-free) struct value`
          : `struct field '${f.name}' expects ${displayName(f.type)}, got ${displayName(a.type)}`,
      );
      return undefined;
    }
    if (isBytesLike(f.type)) {
      const a = this.checkExpr(argNode, f.type);
      if (!a) return undefined;
      if (a.type.kind !== f.type.kind) {
        this.diags.error(
          argNode,
          'JETH226',
          `struct field '${f.name}' expects ${displayName(f.type)}, got ${displayName(a.type)}`,
        );
        return undefined;
      }
      return a;
    }
    if (f.type.kind === 'array' && f.type.length !== undefined && isStaticType(f.type)) {
      const a = this.checkExpr(argNode, f.type);
      if (!a) return undefined;
      // an array literal of exactly N, OR any fixed-array value of the same type (a local / param /
      // storage source, COPIED into the parent at codegen, matching solc).
      if (a.kind === 'arrayLit') {
        if (a.elements.length !== f.type.length) {
          this.diags.error(
            argNode,
            'JETH226',
            `struct field '${f.name}' (${displayName(f.type)}) must be an array literal of ${f.type.length} elements`,
          );
          return undefined;
        }
        return a;
      }
      if (!typesEqual(a.type, f.type)) {
        this.diags.error(
          argNode,
          'JETH226',
          `struct field '${f.name}' expects ${displayName(f.type)}, got ${displayName(a.type)}`,
        );
        return undefined;
      }
      return a;
    }
    if (
      f.type.kind === 'array' &&
      f.type.length === undefined &&
      (isStaticValueType(f.type.element) || f.type.element.kind === 'struct')
    ) {
      const a = this.checkExpr(argNode, f.type);
      if (!a) return undefined;
      // An array LITERAL ([a, b, c]) is a FIXED array (uint256[N]) in solc, which does NOT implicitly
      // convert to a dynamic array (uint256[]) as a constructor field - solc rejects it. Only a true
      // dynamic-array value (a memory/calldata/storage source) is accepted here. A dynamic array of
      // STRUCT elements (Q[]) is accepted identically: the dynamic-struct ABI encoder re-encodes the
      // whole [len][...] array tail (offset table for dynamic-struct elements; contiguous abiHeadWords
      // for static ones), and the source must be a true Q[] value, not a fixed-array literal.
      if (a.kind === 'arrayLit' || !(a.type.kind === 'array' && a.type.length === undefined)) {
        this.diags.error(
          argNode,
          'JETH226',
          `struct field '${f.name}' expects ${displayName(f.type)}, got ${a.kind === 'arrayLit' ? `${displayName(f.type.element)}[${a.elements.length}]` : displayName(a.type)}`,
        );
        return undefined;
      }
      return this.coerce(a, f.type, argNode);
    }
    if (!isStaticValueType(f.type)) {
      this.diags.error(
        argNode,
        'JETH226',
        `struct field '${f.name}' of type ${displayName(f.type)} is not constructible yet`,
      );
      return undefined;
    }
    const a = this.checkExpr(argNode, f.type);
    if (!a) return undefined;
    return this.coerce(a, f.type, argNode);
  }

  /** True if reading `node` has no side effects and is repeatable (an identifier, `this`, or a
   *  property/element access over such - never a call). Used to decide whether a struct value can be
   *  desugared into per-field reads without changing semantics. */
  private isPureReadExpr(node: ts.Expression): boolean {
    if (ts.isIdentifier(node) || node.kind === ts.SyntaxKind.ThisKeyword) return true;
    if (ts.isPropertyAccessExpression(node)) return this.isPureReadExpr(node.expression);
    if (ts.isElementAccessExpression(node))
      return this.isPureReadExpr(node.expression) && this.isPureReadExpr(node.argumentExpression);
    if (ts.isParenthesizedExpression(node)) return this.isPureReadExpr(node.expression);
    if (ts.isNumericLiteral(node) || ts.isBigIntLiteral(node)) return true;
    // a pure VALUE-TYPE cast (address(x)/payable(x)/uN(x)/iN(x)/bytesN(x)/Enum(x)) with pure args is a
    // type conversion, NOT a state-mutating call: repeatable and side-effect-free, like a literal. This
    // keeps a common constant/derived key (m[address(0x..)], m[u8(x)]) out of the side-effecting-key gate.
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      const callee = node.expression.text;
      if (
        callee === 'address' ||
        callee === 'payable' ||
        resolvePrimitiveName(callee) !== undefined ||
        this.isEnumName(callee)
      ) {
        return node.arguments.every((a) => this.isPureReadExpr(a));
      }
    }
    return false;
  }

  /** For a compound-assign / ++ / -- target, find a SIDE-EFFECTING index/key subexpression in the
   *  lvalue navigation chain (m[i++], m[key()], arr[i++], this.s.xs[f()], this.b[g()], nested
   *  m[a()][b()]). Such a target is both READ and WRITTEN, so the desugared `lhs = lhs op rhs`
   *  evaluates that key TWICE (load slot != store slot, and the side effect runs twice); solc
   *  evaluates the lvalue address exactly once. JETH rejects rather than miscompile (the user binds
   *  the key to a const first). A PURE key (identifier, literal, this.x) is evaluated identically on
   *  both sides and stays accepted, byte-identical to solc. */
  private impureLValueKey(node: ts.Expression): ts.Expression | undefined {
    if (ts.isParenthesizedExpression(node)) return this.impureLValueKey(node.expression);
    if (ts.isPropertyAccessExpression(node)) return this.impureLValueKey(node.expression);
    if (ts.isElementAccessExpression(node)) {
      if (node.argumentExpression && !this.isPureReadExpr(node.argumentExpression)) return node.argumentExpression;
      return this.impureLValueKey(node.expression);
    }
    return undefined;
  }

  /** Desugar a non-inline DYNAMIC struct value `src` into an inline constructor that reads each of its
   *  fields: `StructName(src.f0, src.f1, ...)`. This reuses the verified inline struct encoder and is
   *  byte-identical to a field-by-field copy. `src` must be side-effect-free (checked by the caller). */
  private desugarStructCopy(st: JethType & { kind: 'struct' }, src: ts.Expression): Expr | undefined {
    const args: Expr[] = [];
    for (const fld of st.fields) {
      const access = this.synth(ts.factory.createPropertyAccessExpression(src, fld.name), src);
      const a = this.buildStructFieldArg(fld, access);
      if (!a) return undefined;
      args.push(a);
    }
    return { kind: 'structNew', type: st, fields: st.fields, args };
  }

  /** Build the zero/default-value Expr for a STATIC type, used to lower a struct/aggregate memory
   *  local declared without an initializer (`let p: P;`), which solc zero-initializes. A value type
   *  defaults to 0 (bool -> false; enum -> member 0; address/bytesN -> all-zero); a nested static
   *  struct -> an inline `structNew` of its own field defaults; a static fixed-array -> an `arrayLit`
   *  of N element defaults. These are exactly the verified encoders the explicit-constructor path
   *  uses, so the result is byte-identical to solc's `P memory p;`. Caller must pass a STATIC type. */
  private defaultStaticValue(t: JethType): Expr {
    if (t.kind === 'bool') return { kind: 'literalBool', type: t, value: false };
    if (isStaticValueType(t)) return { kind: 'literalInt', type: t, value: 0n };
    if (t.kind === 'struct') {
      const args = t.fields.map((f) => this.defaultStaticValue(f.type));
      return { kind: 'structNew', type: t, fields: t.fields, args };
    }
    // a static fixed-array (length defined, static element)
    const elem = (t as JethType & { kind: 'array' }).element;
    const len = (t as JethType & { kind: 'array' }).length!;
    const elements: Expr[] = [];
    for (let i = 0; i < len; i++) elements.push(this.defaultStaticValue(elem));
    return { kind: 'arrayLit', type: t, elem, elements };
  }

  // Object-literal / spread struct construction: `{ ...base, x: v }` (immutable update) or a
  // full `{ a: x, b: y }` literal. Desugars to the SAME `structNew` a positional StructName(...)
  // produces, so codegen / ABI / storage are byte-identical. Scoped to all-value-field structs:
  // each field value is either an override or a re-read `base.field`, and a value read trivially
  // satisfies structNew's per-field contract (nested/dynamic/array fields still need StructName(...)).
  private checkStructLiteral(node: ts.ObjectLiteralExpression, st: JethType & { kind: 'struct' }): Expr | undefined {
    if (this.typeHasMapping(st)) {
      this.diags.error(
        node,
        'JETH247',
        `struct '${st.name}' contains a mapping and cannot be constructed (mappings are storage-only)`,
      );
      return undefined;
    }
    let base: ts.Expression | undefined;
    const overrides = new Map<string, ts.Expression>();
    for (const p of node.properties) {
      if (ts.isSpreadAssignment(p)) {
        if (base) {
          this.diags.error(p, 'JETH230', 'at most one spread `...base` is allowed in a struct literal');
          return undefined;
        }
        base = p.expression;
        continue;
      }
      if (ts.isPropertyAssignment(p) || ts.isShorthandPropertyAssignment(p)) {
        if (!ts.isIdentifier(p.name)) {
          this.diags.error(p.name, 'JETH231', 'struct field name must be a plain identifier');
          return undefined;
        }
        const fn = p.name.text;
        if (!st.fields.some((fl) => fl.name === fn)) {
          this.diags.error(p.name, 'JETH232', `struct '${st.name}' has no field '${fn}'`);
          return undefined;
        }
        if (overrides.has(fn)) {
          this.diags.error(p.name, 'JETH233', `duplicate field '${fn}' in struct literal`);
          return undefined;
        }
        // shorthand `{ x }` means `x: x` (the field name read as an identifier).
        overrides.set(fn, ts.isPropertyAssignment(p) ? p.initializer : p.name);
        continue;
      }
      this.diags.error(
        p,
        'JETH231',
        'unsupported struct-literal member (use `field: value`, shorthand `field`, or `...base`)',
      );
      return undefined;
    }
    if (base && this.exprHasCall(base)) {
      this.diags.error(
        base,
        'JETH234',
        'struct spread source must be a plain reference (bind a computed value to a const first)',
      );
      return undefined;
    }
    if (base) {
      // The spread source must itself be a value of this exact struct type.
      const b = this.checkExpr(base, st);
      if (!b) return undefined;
      if (!(b.type.kind === 'struct' && b.type.name === st.name)) {
        this.diags.error(base, 'JETH236', `struct spread source must be a ${st.name}, got ${displayName(b.type)}`);
        return undefined;
      }
    }
    const args: Expr[] = [];
    for (const fld of st.fields) {
      const argNode = overrides.get(fld.name);
      if (!argNode) {
        if (!base) {
          this.diags.error(
            node,
            'JETH235',
            `struct literal for '${st.name}' is missing field '${fld.name}' (add it, or spread a base value with ...base)`,
          );
          return undefined;
        }
        // A value field is re-read from the spread base. A non-value field (nested struct / bytes /
        // string / array) cannot be re-read - a field read is not an inline constructor / literal,
        // which the codegen requires - so it must be explicitly provided.
        if (!isStaticValueType(fld.type)) {
          this.diags.error(
            node,
            'JETH229',
            `struct literal for '${st.name}': non-value field '${fld.name}' (${displayName(fld.type)}) must be provided explicitly, not spread from a base`,
          );
          return undefined;
        }
        const reread = this.synth(ts.factory.createPropertyAccessExpression(base, fld.name), base);
        const a = this.checkExpr(reread, fld.type);
        if (!a) return undefined;
        args.push(this.coerce(a, fld.type, reread));
        continue;
      }
      // an explicitly-provided field: full per-field contract (nested struct/bytes/array supported),
      // shared with the positional StructName(...) builder.
      const a = this.buildStructFieldArg(fld, argNode);
      if (!a) return undefined;
      args.push(a);
    }
    return { kind: 'structNew', type: st, fields: st.fields, args };
  }

  /** Resolve `node` to the storage `bytes` LOCATION lvalue (a direct state var, a struct field, a
   *  mapping value, or a bytes[]/Arr<bytes,N> element) for a .push/.pop or b[i]=x mutation. Returns
   *  the lvalue only when it denotes a storage `bytes` (string has no element/push/pop ops in solc),
   *  else undefined so the caller falls through to its other handlers. The yul side computes the
   *  slot from this lvalue exactly as the whole-value assignment does, so any base solc supports works. */
  private bytesLocation(node: ts.Expression): LValue | undefined {
    // Probe via checkLValue, but ROLL BACK any diagnostics + the write flag if the node is not a
    // storage `bytes` location, so the caller can fall through to its other handlers cleanly (e.g.
    // `this.m[k]` first probes `this.m`, which would otherwise emit a spurious JETH153).
    const diagLen = this.diags.items.length;
    const savedWrites = this.currentWritesState;
    const lv = this.checkLValue(node);
    if (
      lv &&
      lv.type.kind === 'bytes' &&
      (lv.kind === 'dynState' || lv.kind === 'mapDynState' || lv.kind === 'strArrayElem' || lv.kind === 'dynPlace')
    ) {
      return lv;
    }
    this.diags.items.length = diagLen;
    this.currentWritesState = savedWrites;
    return undefined;
  }

  private checkArrayMutator(call: ts.CallExpression, method: string, out: Stmt[]): void {
    // this.b.push(<bytes1>) / push() / pop() on a STORAGE `bytes` - a direct state var OR reached
    // through a struct field / mapping value / bytes[] or Arr<bytes,N> element. The receiver is
    // resolved to its bytes LOCATION lvalue (whose slot the yul side computes exactly like the
    // whole-value assignment), so any base solc supports works. Must precede the array resolver
    // (bytes is not an array). push/pop apply to `bytes` only, not `string` (solc parity).
    const recv = (call.expression as ts.PropertyAccessExpression).expression;
    const loc = this.bytesLocation(recv);
    if (loc) {
      this.currentWritesState = true;
      if (method === 'pop') {
        if (call.arguments.length !== 0) this.diags.error(call, 'JETH215', 'pop() takes no arguments');
        out.push({ kind: 'bytesPop', loc });
        return;
      }
      if (call.arguments.length > 1) {
        this.diags.error(call, 'JETH215', 'push(...) takes 0 or 1 arguments');
        return;
      }
      if (call.arguments.length === 0) {
        out.push({ kind: 'bytesPush', loc });
        return;
      }
      const v = this.checkExpr(call.arguments[0]!, BYTES1);
      if (!v) return;
      out.push({ kind: 'bytesPush', loc, value: this.coerce(v, BYTES1, call.arguments[0]!) });
      return;
    }
    const arr = this.resolveArrayExpr((call.expression as ts.PropertyAccessExpression).expression);
    if (!arr) {
      this.diags.error(call, 'JETH210', `'${method}' requires a storage array (this.arr.${method}(...))`);
      return;
    }
    if (arr.base.kind === 'calldataArray') {
      this.diags.error(call, 'JETH214', `a calldata array is read-only (no '${method}')`);
      return;
    }
    if (arr.base.kind === 'fixedArray') {
      this.diags.error(call, 'JETH218', `a fixed-size array has no '${method}' (length is constant)`);
      return;
    }
    this.currentWritesState = true;
    if (method === 'pop') {
      if (call.arguments.length !== 0) this.diags.error(call, 'JETH215', 'pop() takes no arguments');
      out.push({ kind: 'pop', arr });
      return;
    }
    if (call.arguments.length > 1) {
      this.diags.error(call, 'JETH215', 'push(...) takes 0 or 1 arguments');
      return;
    }
    if (call.arguments.length === 0) {
      out.push({ kind: 'push', arr });
      return;
    }
    const v = this.checkExpr(call.arguments[0]!, arr.elem);
    if (!v) return;
    out.push({ kind: 'push', arr, value: this.coerce(v, arr.elem, call.arguments[0]!) });
  }

  /** x++ / x-- / ++x / --x as a STATEMENT (value discarded): x = x +/- 1, on any integer
   *  lvalue (local, state var, struct field, array/mapping element). Checked unless inside
   *  an unchecked block. The pre/post distinction only matters when the value is used,
   *  which is not the statement form. */
  private checkIncDec(operand: ts.Expression, isInc: boolean, node: ts.Node, out: Stmt[]): void {
    const target = this.checkLValue(operand);
    if (!target) return;
    if (!isInteger(target.type)) {
      this.diags.error(
        node,
        'JETH082',
        `'${isInc ? '++' : '--'}' requires an integer operand, got ${displayName(target.type)}`,
      );
      return;
    }
    const idImpure = this.impureLValueKey(operand);
    if (idImpure) {
      this.diags.error(
        idImpure,
        'JETH331',
        `'${isInc ? '++' : '--'}' on an element with a side-effecting index/key would evaluate the index twice (solc evaluates it once); bind the index to a const first`,
      );
      return;
    }
    const left = this.lvalueAsExpr(target);
    const one: Expr = { kind: 'literalInt', type: target.type, value: 1n };
    const combined = this.buildBinary(isInc ? '+' : '-', left, one, node);
    if (!combined) return;
    out.push({ kind: 'assign', target, value: this.coerce(combined, target.type, node) });
  }

  /** x++ / x-- / ++x / --x in value position: yields a value (old for postfix, new for
   *  prefix) and side-effects the lvalue (x = x +/- 1, checked unless in an unchecked block). */
  private checkIncDecExpr(operand: ts.Expression, isInc: boolean, prefix: boolean, node: ts.Node): Expr | undefined {
    const target = this.checkLValue(operand);
    if (!target) return undefined;
    if (!isInteger(target.type)) {
      this.diags.error(
        node,
        'JETH082',
        `'${isInc ? '++' : '--'}' requires an integer operand, got ${displayName(target.type)}`,
      );
      return undefined;
    }
    const idImpure = this.impureLValueKey(operand);
    if (idImpure) {
      this.diags.error(
        idImpure,
        'JETH331',
        `'${isInc ? '++' : '--'}' on an element with a side-effecting index/key would evaluate the index twice (solc evaluates it once); bind the index to a const first`,
      );
      return undefined;
    }
    return {
      kind: 'incDec',
      type: target.type,
      target,
      readExpr: this.lvalueAsExpr(target),
      isInc,
      prefix,
      unchecked: this.currentUnchecked,
    };
  }

  /** True iff `e` is a calldata-source aggregate (a calldata array param echo or a
   *  calldata dynamic-struct echo) - which the storage/memory tuple encoder cannot encode. */
  private isCalldataAggregate(e: Expr): boolean {
    if (e.kind === 'arrayValue') return e.arr.base.kind === 'calldataArray' || e.arr.base.kind === 'cdNestedElem';
    return e.kind === 'cdDynStructValue';
  }

  private checkCondition(expr: ts.Expression): Expr | undefined {
    const e = this.checkExpr(expr, BOOL);
    if (!e) return undefined;
    if (e.type.kind !== 'bool') {
      this.diags.error(expr, 'JETH110', `condition must be bool, got ${displayName(e.type)}`);
      return undefined;
    }
    return e;
  }

  /** Type-check a then/else/loop branch in its own scope; returns the Stmt[]. */
  private checkBranch(node: ts.Statement, returnType: JethType): Stmt[] {
    this.pushScope();
    const out: Stmt[] = [];
    if (ts.isBlock(node)) {
      for (const s of node.statements) this.checkStatement(s, returnType, out);
    } else {
      this.checkStatement(node, returnType, out); // single-statement branch
    }
    this.popScope();
    return out;
  }

  private checkForStatement(node: ts.ForStatement, returnType: JethType, out: Stmt[]): void {
    this.pushScope(); // for-init scope encloses cond, post, body
    let init: Stmt | undefined;
    if (node.initializer) {
      if (ts.isVariableDeclarationList(node.initializer)) {
        if (node.initializer.declarations.length > 1) {
          this.diags.error(node.initializer, 'JETH114', 'for-init supports a single declaration');
        }
        const tmp: Stmt[] = [];
        const d0 = node.initializer.declarations[0];
        if (d0) this.checkLocalDecl(d0, tmp);
        init = tmp[0];
      } else {
        const tmp: Stmt[] = [];
        this.checkExpressionStatement(node.initializer, tmp);
        init = tmp[0];
      }
    }
    const cond = node.condition ? this.checkCondition(node.condition) : undefined;
    let post: Stmt | undefined;
    if (node.incrementor) {
      const tmp: Stmt[] = [];
      this.checkExpressionStatement(node.incrementor, tmp);
      post = tmp[0];
    }
    this.loopDepth++;
    const body = this.checkBranch(node.statement, returnType);
    this.loopDepth--;
    this.popScope();
    out.push({ kind: 'for', init, cond, post, body });
  }

  // Monotonic counter for fresh synthesized-loop variable names (deterministic, no RNG).
  private synthCounter = 0;

  /**
   * Mint a synthesized local name (for-of loop counter, switch discriminant) that cannot collide
   * with any user-visible variable. Cross-scope shadowing is allowed (matching solc), so a synth
   * temp declared in a desugared child block would otherwise SHADOW an enclosing user variable of
   * the same spelling: the user's own references to that name inside the construct would then
   * silently resolve to our temp (e.g. `let __jeth_sw_0 = 42; switch (x) { case 1n: return
   * __jeth_sw_0; }` would return the discriminant, not 42). Bumping past every visible name keeps
   * the synth temp invisible to user code, so the desugar stays sound.
   */
  private freshSynthName(prefix: string): string {
    let name = `${prefix}${this.synthCounter++}`;
    while (this.isVisibleLocal(name)) name = `${prefix}${this.synthCounter++}`;
    return name;
  }

  /** Stamp a synthesized AST node with a real source range + parent so diagnostics that
   *  fire on it can still compute a line/column (getStart scans from node.pos). */
  private synth<T extends ts.Node>(n: T, src: ts.Node): T {
    ts.setTextRange(n, src);
    (n as unknown as { parent: ts.Node }).parent = src.parent ?? src;
    return n;
  }

  /** Rebuild a TS type-annotation node from a resolved JethType, so a synthesized local
   *  decl carries the explicit annotation JETH requires. Covers the types an array element
   *  can be (value/branded/bytes/string/struct/array); other kinds are not iterable elements. */
  private jethTypeToTypeNode(t: JethType, anchor: ts.Node): ts.TypeNode {
    const f = ts.factory;
    const S = <T extends ts.Node>(n: T): T => this.synth(n, anchor);
    const ref = (name: string, args?: ts.TypeNode[]): ts.TypeNode => S(f.createTypeReferenceNode(name, args));
    const brand = (t as { brand?: string }).brand;
    if (brand) return ref(brand);
    switch (t.kind) {
      case 'bool':
        return ref('bool');
      case 'address':
        return ref('address');
      case 'uint':
        return ref('u' + t.bits);
      case 'int':
        return ref('i' + t.bits);
      case 'bytesN':
        return ref('bytes' + t.size);
      case 'bytes':
        return ref('bytes');
      case 'string':
        return ref('string');
      case 'struct':
        return ref(t.name);
      case 'array':
        return t.length !== undefined
          ? ref('Arr', [
              this.jethTypeToTypeNode(t.element, anchor),
              S(f.createLiteralTypeNode(S(f.createNumericLiteral(String(t.length))))),
            ])
          : S(f.createArrayTypeNode(this.jethTypeToTypeNode(t.element, anchor)));
      default:
        return ref('void'); // unreachable for a well-formed array element; re-rejected downstream
    }
  }

  /** True if the expression subtree contains a call (cast, constructor, or method call).
   *  Used to forbid re-evaluating a side-effectful expression once per desugared iteration
   *  / per struct field; the user binds it to a const first. */
  private exprHasCall(node: ts.Node): boolean {
    let found = false;
    const walk = (n: ts.Node): void => {
      if (found) return;
      if (ts.isCallExpression(n)) {
        found = true;
        return;
      }
      ts.forEachChild(n, walk);
    };
    walk(node);
    return found;
  }

  // `for (const v of xs) BODY` desugars to a plain indexed loop the existing checker already
  // handles byte-for-byte:  for (let __i: u256 = 0n; __i < xs.length; __i = __i + 1n) {
  //   const v = xs[__i]; BODY }. The element binding is whatever `const v = xs[__i]` supports
  // on its own (value, or a memory-aggregate copy), so for-of inherits exactly those limits.
  private checkForOfStatement(node: ts.ForOfStatement, returnType: JethType, out: Stmt[]): void {
    if (node.awaitModifier) {
      this.diags.error(node, 'JETH111', 'for-await is not supported (the EVM is synchronous)');
      return;
    }
    const initList = node.initializer;
    if (!ts.isVariableDeclarationList(initList) || initList.declarations.length !== 1) {
      this.diags.error(node.initializer, 'JETH115', 'for-of binding must be a single `const`/`let` variable');
      return;
    }
    if ((initList.flags & (ts.NodeFlags.Const | ts.NodeFlags.Let)) === 0) {
      this.diags.error(node.initializer, 'JETH115', 'for-of binding must use `const` or `let` (no `var`)');
      return;
    }
    const decl = initList.declarations[0]!;
    if (!ts.isIdentifier(decl.name)) {
      this.diags.error(decl.name, 'JETH115', 'for-of binding must be a single identifier (no destructuring)');
      return;
    }
    if (decl.type) {
      this.diags.error(decl.type, 'JETH116', 'for-of binding has an inferred element type; drop the annotation');
      return;
    }
    const iterable = node.expression;
    if (this.exprHasCall(iterable)) {
      this.diags.error(
        iterable,
        'JETH117',
        'for-of iterable must be a plain array reference (bind a computed value to a const first)',
      );
      return;
    }
    const probe = this.checkExpr(iterable);
    if (!probe) return;
    if (probe.type.kind !== 'array') {
      this.diags.error(iterable, 'JETH118', `for-of requires an array, got ${displayName(probe.type)}`);
      return;
    }
    const elemType = probe.type.element;
    const f = ts.factory;
    const S = <T extends ts.Node>(n: T): T => this.synth(n, iterable);
    const idxName = this.freshSynthName('__jeth_of_');
    const idx = (): ts.Identifier => S(f.createIdentifier(idxName));
    const initDecl = S(
      f.createVariableDeclaration(
        idxName,
        undefined,
        S(f.createTypeReferenceNode('u256', undefined)),
        S(f.createBigIntLiteral('0n')),
      ),
    );
    const synInit = S(f.createVariableDeclarationList([initDecl], ts.NodeFlags.Let));
    const cond = S(
      f.createBinaryExpression(
        idx(),
        ts.SyntaxKind.LessThanToken,
        S(f.createPropertyAccessExpression(iterable, 'length')),
      ),
    );
    const incr = S(
      f.createBinaryExpression(
        idx(),
        ts.SyntaxKind.EqualsToken,
        S(f.createBinaryExpression(idx(), ts.SyntaxKind.PlusToken, S(f.createBigIntLiteral('1n')))),
      ),
    );
    const elemDecl = S(
      f.createVariableDeclaration(
        decl.name,
        undefined,
        this.jethTypeToTypeNode(elemType, iterable),
        S(f.createElementAccessExpression(iterable, idx())),
      ),
    );
    const elemFlags = initList.flags & ts.NodeFlags.Const ? ts.NodeFlags.Const : ts.NodeFlags.Let;
    const elemStmt = S(f.createVariableStatement(undefined, S(f.createVariableDeclarationList([elemDecl], elemFlags))));
    const bodyBlock = S(f.createBlock([elemStmt, node.statement], true));
    const forStmt = S(f.createForStatement(synInit, cond, incr, bodyBlock));
    this.checkForStatement(forStmt, returnType, out);
  }

  /** Collect `break` statements that target THIS switch (not enclosed by a nested loop/switch,
   *  which consume their own break). Used to forbid an early `break` mid-case. */
  private straySwitchBreaks(stmts: readonly ts.Statement[]): ts.Node[] {
    const found: ts.Node[] = [];
    const walk = (n: ts.Node): void => {
      if (
        ts.isForStatement(n) ||
        ts.isForOfStatement(n) ||
        ts.isForInStatement(n) ||
        ts.isWhileStatement(n) ||
        ts.isDoStatement(n) ||
        ts.isSwitchStatement(n)
      )
        return; // own break target
      if (n.kind === ts.SyntaxKind.BreakStatement) {
        found.push(n);
        return;
      }
      ts.forEachChild(n, walk);
    };
    for (const s of stmts) walk(s);
    return found;
  }

  // `switch (disc) { case A: ... break; case B: case C: ... return x; default: ... }` desugars to a
  // nested if/else chain over a single evaluation of the discriminant, reusing the if-codegen. JETH
  // is STRICTER than TypeScript: a non-empty case must terminate (break / return / revert / continue)
  // so there is no implicit fall-through (an EMPTY case label still shares the next case's body), and
  // a switch over an enum with no `default` must cover every member (exhaustiveness).
  private checkSwitchStatement(node: ts.SwitchStatement, returnType: JethType, out: Stmt[]): void {
    const disc = node.expression;
    const probe = this.checkExpr(disc);
    if (!probe) return;
    const dt = probe.type;
    if (!isStaticValueType(dt)) {
      this.diags.error(
        disc,
        'JETH281',
        `switch discriminant must be a value type (uint/int/enum/bool/address/bytesN), got ${displayName(dt)}`,
      );
      return;
    }
    const clauses = node.caseBlock.clauses;
    // Group consecutive EMPTY case labels with the next clause that has a body. default must be last.
    const groups: { labels: ts.Expression[]; body: ts.Statement[]; node: ts.Node }[] = [];
    let defaultBody: ts.Statement[] | undefined;
    let pending: ts.Expression[] = [];
    for (let i = 0; i < clauses.length; i++) {
      const cl = clauses[i]!;
      if (ts.isDefaultClause(cl)) {
        if (i !== clauses.length - 1) {
          this.diags.error(cl, 'JETH282', 'a switch `default` must be the last clause');
          return;
        }
        if (pending.length > 0) {
          this.diags.error(
            cl,
            'JETH283',
            'a `case` label that falls through to `default` is not supported; give it a body',
          );
          return;
        }
        defaultBody = [...cl.statements];
        continue;
      }
      pending.push(cl.expression);
      if (cl.statements.length > 0) {
        groups.push({ labels: pending, body: [...cl.statements], node: cl });
        pending = [];
      }
    }
    if (pending.length > 0) {
      this.diags.error(
        node,
        'JETH283',
        'a trailing `case` label with no body is not supported (it would fall off the end)',
      );
      return;
    }

    // Each group body must terminate; drop a trailing `break` (the case end) and forbid a stray one.
    for (const g of groups) {
      const last = g.body[g.body.length - 1];
      const terminated = last !== undefined && (last.kind === ts.SyntaxKind.BreakStatement || this.stmtDiverts(last));
      if (!terminated) {
        this.diags.error(
          g.node,
          'JETH284',
          'a switch case must end in `break`, `return`, `revert(...)`, or `continue` (implicit fall-through is not allowed; add a trailing `break` after a nested switch)',
        );
        return;
      }
      if (last!.kind === ts.SyntaxKind.BreakStatement) g.body = g.body.slice(0, -1); // case terminator
      const strays = this.straySwitchBreaks(g.body);
      if (strays.length > 0) {
        this.diags.error(
          strays[0]!,
          'JETH285',
          'an early `break` in a switch case is not supported (a case ends only at its final `break`)',
        );
        return;
      }
    }
    if (defaultBody) {
      const strays = this.straySwitchBreaks(defaultBody);
      // a default body may end in a no-op break too; drop a trailing break and reject early ones.
      const last = defaultBody[defaultBody.length - 1];
      if (last && last.kind === ts.SyntaxKind.BreakStatement) defaultBody = defaultBody.slice(0, -1);
      const stray2 = this.straySwitchBreaks(defaultBody);
      if (stray2.length > 0) {
        this.diags.error(stray2[0]!, 'JETH285', 'an early `break` in a switch `default` is not supported');
        return;
      }
      void strays;
    }

    // Exhaustiveness: a switch over an enum with no default must cover every member. Resolve each
    // label to its constant value (an enum-member label is a literalInt) and collect the coverage.
    const labelExprs: { node: ts.Expression; expr: Expr | undefined }[] = [];
    for (const g of groups) for (const l of g.labels) labelExprs.push({ node: l, expr: this.checkExpr(l, dt) });
    // Stricter lint: a duplicate CONSTANT case label is a dead arm (the first match wins) and almost
    // always a bug. Reject it (constant int/enum/address-literal and bool labels are deduplicated).
    const seenInt = new Set<bigint>();
    const seenBool = new Set<boolean>();
    for (const { node: ln, expr } of labelExprs) {
      if (expr?.kind === 'literalInt') {
        if (seenInt.has(expr.value)) {
          this.diags.error(ln, 'JETH287', `duplicate case label ${expr.value} in switch`);
          return;
        }
        seenInt.add(expr.value);
      } else if (expr?.kind === 'literalBool') {
        if (seenBool.has(expr.value)) {
          this.diags.error(ln, 'JETH287', `duplicate case label ${expr.value} in switch`);
          return;
        }
        seenBool.add(expr.value);
      }
    }
    if (isEnum(dt) && !defaultBody) {
      const covered = new Set<bigint>();
      for (const { expr } of labelExprs) if (expr && expr.kind === 'literalInt') covered.add(expr.value);
      const n = (dt as { enumMembers: string[] }).enumMembers.length;
      const missing: string[] = [];
      for (let i = 0; i < n; i++)
        if (!covered.has(BigInt(i))) missing.push((dt as { enumMembers: string[] }).enumMembers[i]!);
      if (missing.length > 0) {
        this.diags.error(
          node,
          'JETH286',
          `switch over enum '${displayName(dt)}' is not exhaustive; missing: ${missing.join(', ')} (add the cases or a \`default\`)`,
        );
        return;
      }
    }

    // Desugar: `const __sw: T = disc; if (__sw == L..) { body } else if (..) {..} else { default }`.
    const f = ts.factory;
    const S = <T extends ts.Node>(x: T): T => this.synth(x, disc);
    const swName = this.freshSynthName('__jeth_sw_');
    const swId = (): ts.Identifier => S(f.createIdentifier(swName));
    const decl = S(f.createVariableDeclaration(swName, undefined, this.jethTypeToTypeNode(dt, disc), disc));
    const declStmt = S(
      f.createVariableStatement(undefined, S(f.createVariableDeclarationList([decl], ts.NodeFlags.Const))),
    );
    const eqOr = (labels: ts.Expression[]): ts.Expression =>
      labels
        .map((l) => S(f.createBinaryExpression(swId(), ts.SyntaxKind.EqualsEqualsToken, l)) as ts.Expression)
        .reduce((a, b) => S(f.createBinaryExpression(a, ts.SyntaxKind.BarBarToken, b)));
    let chain: ts.Statement | undefined = defaultBody ? S(f.createBlock(defaultBody, true)) : undefined;
    for (let i = groups.length - 1; i >= 0; i--) {
      const g = groups[i]!;
      chain = S(f.createIfStatement(eqOr(g.labels), S(f.createBlock(g.body, true)), chain));
    }
    const block = S(f.createBlock(chain ? [declStmt, chain] : [declStmt], true));
    // Emit as a scoped block so the synthesized discriminant temp does not leak.
    this.checkStatement(block, returnType, out);
  }

  /** True if executing `s` never falls through to the textually-following statement (it always
   *  returns / reverts / throws / continues, or is an if-else whose branches all divert, or a block
   *  whose last statement diverts). Conservative: a nested switch is not counted (it needs an
   *  explicit trailing `break`), and `break` is handled separately as the case terminator. */
  private stmtDiverts(s: ts.Statement): boolean {
    if (ts.isReturnStatement(s) || this.isRevertOrThrow(s) || s.kind === ts.SyntaxKind.ContinueStatement) return true;
    if (ts.isBlock(s)) {
      const l = s.statements[s.statements.length - 1];
      return !!l && this.stmtDiverts(l);
    }
    if (ts.isIfStatement(s))
      return !!s.elseStatement && this.stmtDiverts(s.thenStatement) && this.stmtDiverts(s.elseStatement);
    // A switch diverts iff it has a `default` (the "else") AND every non-empty clause body diverts.
    // (An empty label falls through to the next clause's body, so skip it.) Mirrors the if/else rule.
    if (ts.isSwitchStatement(s)) {
      const clauses = s.caseBlock.clauses;
      if (!clauses.some(ts.isDefaultClause)) return false;
      for (const cl of clauses) {
        if (cl.statements.length === 0) continue;
        const last = cl.statements[cl.statements.length - 1]!;
        if (!this.stmtDiverts(last)) return false;
      }
      return true;
    }
    return false;
  }

  /** True if a statement is a `revert(...)` / custom-error revert / `throw` (a terminating stmt). */
  private isRevertOrThrow(s: ts.Statement): boolean {
    if (s.kind === ts.SyntaxKind.ThrowStatement) return true;
    if (ts.isExpressionStatement(s) && ts.isCallExpression(s.expression) && ts.isIdentifier(s.expression.expression)) {
      return s.expression.expression.text === 'revert';
    }
    return false;
  }

  // ---- require / revert / custom errors ------------------------------------

  private checkRequire(call: ts.CallExpression, out: Stmt[]): void {
    const args = call.arguments;
    if (args.length < 1 || args.length > 2) {
      this.diags.error(call, 'JETH120', `require(...) takes 1 or 2 arguments, got ${args.length}`);
      return;
    }
    const cond = this.checkExpr(args[0]!, BOOL);
    if (!cond) return;
    if (cond.type.kind !== 'bool') {
      this.diags.error(args[0]!, 'JETH121', `require condition must be bool, got ${displayName(cond.type)}`);
      return;
    }
    const reason: RevertReason | undefined = args.length === 2 ? this.checkRevertReason(args[1]!) : { kind: 'empty' };
    if (reason) out.push({ kind: 'require', cond, reason });
  }

  /** assert(cond): an invariant check. On failure -> Panic(0x01) (matches solc). Unlike
   *  require, assert takes no message and always reverts with the assert panic code. */
  private checkAssert(call: ts.CallExpression, out: Stmt[]): void {
    const args = call.arguments;
    if (args.length !== 1) {
      this.diags.error(call, 'JETH120', `assert(...) takes 1 argument, got ${args.length}`);
      return;
    }
    const cond = this.checkExpr(args[0]!, BOOL);
    if (!cond) return;
    if (cond.type.kind !== 'bool') {
      this.diags.error(args[0]!, 'JETH121', `assert condition must be bool, got ${displayName(cond.type)}`);
      return;
    }
    out.push({ kind: 'require', cond, reason: { kind: 'panic', code: 0x01 } });
  }

  private checkRevert(call: ts.CallExpression, out: Stmt[]): void {
    const args = call.arguments;
    if (args.length > 1) {
      this.diags.error(call, 'JETH122', `revert(...) takes 0 or 1 arguments, got ${args.length}`);
      return;
    }
    const reason: RevertReason | undefined = args.length === 1 ? this.checkRevertReason(args[0]!) : { kind: 'empty' };
    if (reason) out.push({ kind: 'revert', reason });
  }

  private checkRevertReason(node: ts.Expression): RevertReason | undefined {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      return { kind: 'errorString', message: new TextEncoder().encode(node.text) };
    }
    // a custom-error constructor: a call whose callee is a DECLARED error name. A call to any other
    // identifier (e.g. the type-conversion `string(b)`) is NOT an error call - it falls through to the
    // runtime-string path below, matching solc which lowers a string-typed reason to Error(string).
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && this.errorsByName.has(node.expression.text)) {
      return this.checkErrorConstructor(node);
    }
    // a template literal `bad: ${x}` is a runtime string-typed expression (it desugars to string.concat);
    // it falls through to the dynamic Error(string) path below, byte-identical to solc revert(string.concat).
    // any runtime string-typed expression (a string param, this.s, a string(bytes) cast, a ternary
    // whose branches are strings, a concat / template, ...) -> dynamic Error(string), matching solc. Snapshot the
    // diagnostic length so an inner check that does not yield a string can be rolled back to emit a
    // single, precise reason diagnostic (mirrors the trial-check idiom at resolveOverload).
    const diagLen = this.diags.items.length;
    const e = this.checkExpr(node, STRING);
    if (e && e.type.kind === 'string') return { kind: 'errorStringDyn', value: e };
    this.diags.items.length = diagLen; // discard the inner trial diagnostics
    // a call to an UNKNOWN identifier (no such declared error, not a type-conversion that yields a
    // string) -> report it as an unknown custom error, matching `revert(Foo())`'s prior behaviour.
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && e === undefined) {
      this.diags.error(node.expression, 'JETH129', `unknown custom error '${node.expression.text}'`);
      return undefined;
    }
    // a value reference (a param / field access) that resolves to a non-string -> JETH206 (it WAS a
    // candidate Error(string) value, just the wrong type); any other non-string shape -> JETH123.
    if (e && (ts.isIdentifier(node) || ts.isPropertyAccessExpression(node))) {
      this.diags.error(node, 'JETH206', `Error(string) message must be a string, got ${displayName(e.type)}`);
    } else {
      this.diags.error(
        node,
        'JETH123',
        'revert/require reason must be a string (literal or value) or a custom error constructor',
      );
    }
    return undefined;
  }

  private checkErrorConstructor(node: ts.CallExpression): RevertReason | undefined {
    const name = (node.expression as ts.Identifier).text;
    const decl = this.errorsByName.get(name);
    if (!decl) {
      this.diags.error(node.expression, 'JETH129', `unknown custom error '${name}'`);
      return undefined;
    }
    if (node.arguments.length !== decl.params.length) {
      this.diags.error(
        node,
        'JETH130',
        `error '${name}' expects ${decl.params.length} argument(s), got ${node.arguments.length}`,
      );
      return undefined;
    }
    const args: Expr[] = [];
    for (let i = 0; i < decl.params.length; i++) {
      const want = decl.params[i]!.type;
      const e = this.checkExpr(node.arguments[i]!, want);
      if (!e) return undefined;
      args.push(this.coerce(e, want, node.arguments[i]!));
    }
    return { kind: 'custom', decl, args };
  }

  // ---- Phase 6: external low-level calls -----------------------------------

  /** The receiver of a `<recv>.<method>(...)` external call, if `<recv>` is an address. */
  private externalCallReceiver(node: ts.CallExpression): Expr | undefined {
    if (!ts.isPropertyAccessExpression(node.expression)) return undefined;
    const recv = this.checkExpr(node.expression.expression);
    if (!recv || recv.type.kind !== 'address') return undefined;
    return recv;
  }

  /** Parse the single object-literal argument shared by call/staticcall/tryCall/tryStaticcall.
   *  Validates fields (data required; value rejected on a staticcall; success required on the
   *  checked forms and forbidden on the try forms; no unknown fields). Returns the lowered
   *  data/value/gas exprs and the ordered success checks, or undefined (with a diagnostic). */
  private checkExternalCallShape(
    node: ts.CallExpression,
    method: string,
    op: 'call' | 'staticcall',
    isTry: boolean,
  ):
    | { data: Expr; value?: Expr; gas?: Expr; checks: SuccessCheck[]; decode?: { types: JethType[]; tuple: boolean } }
    | undefined {
    if (node.arguments.length !== 1 || !ts.isObjectLiteralExpression(node.arguments[0]!)) {
      this.diags.error(node, 'JETH300', `${method}(...) takes a single object literal { data, ... }`);
      return undefined;
    }
    const obj = node.arguments[0] as ts.ObjectLiteralExpression;
    const fields = new Map<string, ts.Expression>();
    for (const p of obj.properties) {
      if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name)) {
        if (fields.has(p.name.text)) {
          this.diags.error(p.name, 'JETH301', `duplicate field '${p.name.text}'`);
          return undefined;
        }
        fields.set(p.name.text, p.initializer);
      } else if (ts.isShorthandPropertyAssignment(p)) {
        if (fields.has(p.name.text)) {
          this.diags.error(p.name, 'JETH301', `duplicate field '${p.name.text}'`);
          return undefined;
        }
        fields.set(p.name.text, p.name);
      } else {
        this.diags.error(p, 'JETH301', `${method}(...) options must be plain 'field: value' members`);
        return undefined;
      }
    }
    const allowed = new Set(['data', 'gas']);
    if (op === 'call') allowed.add('value'); // staticcall cannot send value
    if (!isTry) {
      allowed.add('success');
      allowed.add('decode');
    } // decode/success only on the checked forms
    for (const k of fields.keys()) {
      if (!allowed.has(k)) {
        // give a precise message for the structural rules.
        if (k === 'value' && op === 'staticcall')
          this.diags.error(obj, 'JETH302', `staticcall cannot send value (remove 'value')`);
        else if (k === 'success' && isTry)
          this.diags.error(
            obj,
            'JETH303',
            `${method}(...) is the raw escape hatch and takes no 'success' (handle [ok, ret] yourself)`,
          );
        else if (k === 'decode' && isTry)
          this.diags.error(
            obj,
            'JETH303',
            `${method}(...) is the raw escape hatch and takes no 'decode' (decode the [ok, ret] bytes yourself)`,
          );
        else
          this.diags.error(
            obj,
            'JETH301',
            `${method}(...): unknown option '${k}' (allowed: ${[...allowed].join(', ')})`,
          );
        return undefined;
      }
    }
    const dataNode = fields.get('data');
    if (!dataNode) {
      this.diags.error(obj, 'JETH304', `${method}(...) requires a 'data' (bytes) field`);
      return undefined;
    }
    const data = this.checkExpr(dataNode, BYTES);
    if (!data) return undefined;
    if (data.type.kind !== 'bytes') {
      this.diags.error(dataNode, 'JETH305', `${method}(...) 'data' must be bytes, got ${displayName(data.type)}`);
      return undefined;
    }
    let value: Expr | undefined;
    if (op === 'call') {
      const vNode = fields.get('value');
      if (vNode) {
        const v = this.checkExpr(vNode, U256);
        if (!v) return undefined;
        if (!isInteger(v.type)) {
          this.diags.error(vNode, 'JETH306', `${method}(...) 'value' must be an integer, got ${displayName(v.type)}`);
          return undefined;
        }
        value = this.coerce(v, U256, vNode);
      }
    }
    let gas: Expr | undefined;
    const gNode = fields.get('gas');
    if (gNode) {
      const g = this.checkExpr(gNode, U256);
      if (!g) return undefined;
      if (!isInteger(g.type)) {
        this.diags.error(gNode, 'JETH306', `${method}(...) 'gas' must be an integer, got ${displayName(g.type)}`);
        return undefined;
      }
      gas = this.coerce(g, U256, gNode);
    }
    // success checks (checked forms only). A single { condition, revert } OR an array of them.
    const checks: SuccessCheck[] = [];
    if (!isTry) {
      const sNode = fields.get('success');
      if (!sNode) {
        this.diags.error(
          obj,
          'JETH307',
          `${method}(...) requires a 'success' field (one { condition, revert } object or an array of them)`,
        );
        return undefined;
      }
      const entries: ts.Expression[] = ts.isArrayLiteralExpression(sNode)
        ? sNode.elements.filter((el): el is ts.Expression => !ts.isOmittedExpression(el))
        : [sNode];
      if (entries.length === 0) {
        this.diags.error(
          sNode,
          'JETH307',
          `${method}(...) 'success' must contain at least one { condition, revert } entry`,
        );
        return undefined;
      }
      for (const entry of entries) {
        const c = this.checkSuccessEntry(entry, method);
        if (!c) return undefined;
        checks.push(c);
      }
    }
    // optional `decode: T` / `decode: [T1, ...]` (checked forms only): decode the post-success
    // returndata directly. This is exact sugar for `addr.call({...}).decode(T)` - it wraps the call's
    // bytes result in the same abi.decode codec, with the same supported-type rules and validation.
    let decode: { types: JethType[]; tuple: boolean } | undefined;
    if (!isTry) {
      const decNode = fields.get('decode');
      if (decNode) {
        const tuple = ts.isArrayLiteralExpression(decNode);
        const typeExprs = tuple ? [...(decNode as ts.ArrayLiteralExpression).elements] : [decNode];
        if (tuple && typeExprs.length < 1) {
          this.diags.error(decNode, 'JETH321', `${method}(...) 'decode' tuple type list must have at least one type`);
          return undefined;
        }
        const types: JethType[] = [];
        for (const te of typeExprs) {
          const t = this.resolveTypeExpr(te as ts.Expression);
          if (!t) {
            this.diags.error(
              te,
              'JETH321',
              `${method}(...) 'decode' must be a type name, \`T[]\`, \`Arr<T, N>\`, or a tuple \`[T1, T2, ...]\` of those`,
            );
            return undefined;
          }
          if (!this.decodeSupported(t)) {
            this.diags.error(
              te,
              'JETH322',
              `${method}(...) 'decode' does not support decoding to '${displayName(t)}' yet (supported: value types, bytes, string, T[], Arr<T, N>, and structs of those)`,
            );
            return undefined;
          }
          types.push(t);
        }
        decode = { types, tuple };
      }
    }
    return { data, value, gas, checks, decode };
  }

  /** One success entry `{ condition: <bool with this.ok/this.data>, revert: "msg" | E(args) }`. */
  private checkSuccessEntry(entry: ts.Expression, method: string): SuccessCheck | undefined {
    if (!ts.isObjectLiteralExpression(entry)) {
      this.diags.error(entry, 'JETH308', `${method}(...) success entry must be an object { condition, revert }`);
      return undefined;
    }
    let condNode: ts.Expression | undefined;
    let revertNode: ts.Expression | undefined;
    for (const p of entry.properties) {
      if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name)) {
        if (p.name.text === 'condition') condNode = p.initializer;
        else if (p.name.text === 'revert') revertNode = p.initializer;
        else {
          this.diags.error(
            p.name,
            'JETH308',
            `success entry: unknown field '${p.name.text}' (allowed: condition, revert)`,
          );
          return undefined;
        }
      } else {
        this.diags.error(p, 'JETH308', 'success entry options must be plain `condition:` / `revert:` members');
        return undefined;
      }
    }
    if (!condNode) {
      this.diags.error(entry, 'JETH308', 'success entry is missing `condition`');
      return undefined;
    }
    if (!revertNode) {
      this.diags.error(entry, 'JETH308', 'success entry is missing `revert`');
      return undefined;
    }
    // Bind `this.ok` (bool) + `this.data` (bytes) ONLY while checking the condition; restore after so
    // they never leak. Nested calls are not expected, but save/restore makes it safe anyway.
    const saved = this.callResultBindings;
    this.callResultBindings = new Map<string, JethType>([
      ['ok', BOOL],
      ['data', BYTES],
    ]);
    const cond = this.checkExpr(condNode, BOOL);
    this.callResultBindings = saved;
    if (!cond) return undefined;
    if (cond.type.kind !== 'bool') {
      this.diags.error(condNode, 'JETH309', `success condition must be bool, got ${displayName(cond.type)}`);
      return undefined;
    }
    const reason = this.checkRevertReason(revertNode);
    if (!reason) return undefined;
    return { cond, reason };
  }

  /** `<addr>.call/staticcall({...})` in value position -> a bytes Expr. The try forms are only valid
   *  in a tuple destructuring (`let [ok, ret] = addr.tryCall({...})`), so they error here. */
  private checkExternalCall(node: ts.CallExpression, method: string): Expr | undefined {
    const recv = this.externalCallReceiver(node);
    if (!recv) {
      // not an address receiver: let other handling report it; emit a precise error.
      this.diags.error(node, 'JETH310', `${method}(...) requires an address receiver`);
      return undefined;
    }
    if (method === 'tryCall' || method === 'tryStaticcall') {
      this.diags.error(node, 'JETH311', `${method}(...) returns [bool, bytes]; bind it with 'let [ok, ret] = ...'`);
      return undefined;
    }
    const op: 'call' | 'staticcall' = method === 'staticcall' ? 'staticcall' : 'call';
    const shape = this.checkExternalCallShape(node, method, op, false);
    if (!shape) return undefined;
    // mutability: a `call` may mutate callee/this state -> non-view; a `staticcall` is read-only (env).
    if (op === 'call') this.currentWritesState = true;
    else this.currentReadsEnv = true;
    const expr: Expr = {
      kind: 'extCall',
      type: BYTES,
      op,
      addr: recv,
      data: shape.data,
      value: shape.value,
      gas: shape.gas,
      checks: shape.checks,
    };
    if (shape.decode) {
      // `decode: [T1, ...]` yields a tuple; it must be destructured (handled by resolveCallDecodeTuple).
      if (shape.decode.tuple) {
        this.diags.error(
          node,
          'JETH323',
          `a multi-type ${method}(...) 'decode' yields a tuple; bind it with a destructuring \`let [a, b] = ${method}(...)\``,
        );
        return undefined;
      }
      // `decode: T` yields one value: wrap the call's bytes result in the same abi.decode codec.
      return { kind: 'abiDecode', type: shape.decode.types[0]!, data: expr };
    }
    return expr;
  }

  /** Is `node` the interface-wrapper call shape `IFoo(addr)` / `IFoo(addr, { value?, gas? })`?
   *  Returns the interface name when it is (whether or not the args are valid), else undefined. */
  private interfaceWrapperName(node: ts.Expression): string | undefined {
    if (!ts.isCallExpression(node) || !ts.isIdentifier(node.expression)) return undefined;
    const nm = node.expression.text;
    return this.interfacesByName.has(nm) && !this.isVisibleLocal(nm) ? nm : undefined;
  }

  /** Resolve a high-level typed interface call `IFoo(addr [, { value?, gas? }]).method(args)`.
   *  Returns the lowered extCall expr (bubble + codeGuard set) plus the declared return shape, or
   *  'handled' when the node IS an interface call/wrapper but is misused (a precise diagnostic was
   *  emitted; stop), or undefined when `node` is not an interface call (let other handling decide). */
  private resolveInterfaceCall(
    node: ts.Expression,
  ): { call: Expr & { kind: 'extCall' }; returnType: JethType; returnTypes?: JethType[] } | 'handled' | undefined {
    // shape: a CallExpression whose callee is `IFoo(addr [, opts]).method` (a PropertyAccess whose base
    // is the interface wrapper call). The bare wrapper `IFoo(addr)` (no .method() applied) is rejected
    // separately by checkExpr (an interface value is not usable on its own).
    if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) return undefined;
    const pa = node.expression;
    const ifaceName = this.interfaceWrapperName(pa.expression);
    if (!ifaceName) return undefined;
    const iface = this.interfacesByName.get(ifaceName)!;
    const wrapper = pa.expression as ts.CallExpression;
    const methodName = pa.name.text;

    // ---- the wrapper: IFoo(addr) or IFoo(addr, { value?, gas? }) ----
    if (wrapper.arguments.length < 1 || wrapper.arguments.length > 2) {
      this.diags.error(
        wrapper,
        'JETH349',
        `${ifaceName}(...) takes an address and an optional { value?, gas? } options object`,
      );
      return 'handled';
    }
    const addr = this.checkExpr(wrapper.arguments[0]!, ADDRESS);
    if (!addr) return 'handled';
    if (addr.type.kind !== 'address') {
      this.diags.error(
        wrapper.arguments[0]!,
        'JETH350',
        `${ifaceName}(...) requires an address, got ${displayName(addr.type)}`,
      );
      return 'handled';
    }
    const recv = this.coerce(addr, ADDRESS, wrapper.arguments[0]!);

    // ---- the method ----
    const method = iface.methods.get(methodName);
    if (!method) {
      this.diags.error(pa, 'JETH351', `interface '${ifaceName}' has no method '${methodName}'`);
      return 'handled';
    }
    const op: 'call' | 'staticcall' =
      method.mutability === 'view' || method.mutability === 'pure' ? 'staticcall' : 'call';

    // ---- wrapper options: { value?, gas? } (value only on a @payable method) ----
    let value: Expr | undefined;
    let gas: Expr | undefined;
    if (wrapper.arguments.length === 2) {
      const optNode = wrapper.arguments[1]!;
      if (!ts.isObjectLiteralExpression(optNode)) {
        this.diags.error(optNode, 'JETH352', `${ifaceName}(...) options must be an object literal { value?, gas? }`);
        return 'handled';
      }
      const fields = new Map<string, ts.Expression>();
      for (const p of optNode.properties) {
        if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name)) {
          if (fields.has(p.name.text)) {
            this.diags.error(p.name, 'JETH352', `duplicate option '${p.name.text}'`);
            return 'handled';
          }
          fields.set(p.name.text, p.initializer);
        } else if (ts.isShorthandPropertyAssignment(p)) {
          if (fields.has(p.name.text)) {
            this.diags.error(p.name, 'JETH352', `duplicate option '${p.name.text}'`);
            return 'handled';
          }
          fields.set(p.name.text, p.name);
        } else {
          this.diags.error(p, 'JETH352', `${ifaceName}(...) options must be plain 'field: value' members`);
          return 'handled';
        }
      }
      for (const k of fields.keys()) {
        if (k !== 'value' && k !== 'gas') {
          this.diags.error(optNode, 'JETH352', `${ifaceName}(...): unknown option '${k}' (allowed: value, gas)`);
          return 'handled';
        }
      }
      const vNode = fields.get('value');
      if (vNode) {
        // solc: "Cannot set option value on a non-payable function type".
        if (method.mutability !== 'payable') {
          this.diags.error(
            vNode,
            'JETH353',
            `cannot set option 'value' on the non-payable method '${ifaceName}.${methodName}'`,
          );
          return 'handled';
        }
        const v = this.checkExpr(vNode, U256);
        if (!v) return 'handled';
        if (!isInteger(v.type)) {
          this.diags.error(
            vNode,
            'JETH306',
            `${ifaceName}(...) 'value' must be an integer, got ${displayName(v.type)}`,
          );
          return 'handled';
        }
        value = this.coerce(v, U256, vNode);
      }
      const gNode = fields.get('gas');
      if (gNode) {
        const g = this.checkExpr(gNode, U256);
        if (!g) return 'handled';
        if (!isInteger(g.type)) {
          this.diags.error(gNode, 'JETH306', `${ifaceName}(...) 'gas' must be an integer, got ${displayName(g.type)}`);
          return 'handled';
        }
        gas = this.coerce(g, U256, gNode);
      }
    }

    // ---- the arguments: check + coerce to the method's param types ----
    if (node.arguments.length !== method.params.length) {
      this.diags.error(
        node,
        'JETH354',
        `'${ifaceName}.${methodName}' takes ${method.params.length} argument(s), got ${node.arguments.length}`,
      );
      return 'handled';
    }
    const args: Expr[] = [];
    for (let i = 0; i < method.params.length; i++) {
      const pt = method.params[i]!.type;
      const a = this.checkExpr(node.arguments[i]!, pt);
      if (!a) return 'handled';
      if (pt.kind === 'struct') {
        if (a.type.kind !== 'struct' || a.type.name !== pt.name) {
          this.diags.error(
            node.arguments[i]!,
            'JETH355',
            `argument ${i + 1} of '${ifaceName}.${methodName}' expects ${displayName(pt)}, got ${displayName(a.type)}`,
          );
          return 'handled';
        }
        args.push(a);
      } else {
        args.push(this.coerce(a, pt, node.arguments[i]!));
      }
    }

    // calldata = selector ++ abi.encode(args): a bytes value via the abiEncode codec with a precomputed
    // bytes4 selector literal (left-aligned in the high 4 bytes, exactly like abi.encodeWithSelector).
    const selExpr: Expr = {
      kind: 'literalInt',
      type: { kind: 'bytesN', size: 4 },
      value: BigInt('0x' + method.selector) << 224n,
    };
    const data: Expr = { kind: 'abiEncode', type: BYTES, packed: false, args, selector: selExpr };

    // mutability: a CALL may mutate callee/this state (non-view); a STATICCALL is a read-only env effect.
    if (op === 'call') this.currentWritesState = true;
    else this.currentReadsEnv = true;

    const call: Expr & { kind: 'extCall' } = {
      kind: 'extCall',
      type: BYTES,
      op,
      addr: recv,
      data,
      value,
      gas,
      checks: [],
      bubble: true,
      codeGuard: true,
    };
    return { call, returnType: method.returnType, returnTypes: method.returnTypes };
  }

  /** `let [ok, ret] = addr.tryCall/tryStaticcall({...})`: resolve the destructuring source +
   *  component types ([bool, bytes]), or undefined if `node` is not a try-call. */
  private resolveTryCall(node: ts.Expression): { source: DestructureSource; types: JethType[] } | undefined {
    if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) return undefined;
    const method = node.expression.name.text;
    if (method !== 'tryCall' && method !== 'tryStaticcall') return undefined;
    const recv = this.externalCallReceiver(node);
    if (!recv) {
      this.diags.error(node, 'JETH310', `${method}(...) requires an address receiver`);
      return undefined;
    }
    const op: 'call' | 'staticcall' = method === 'tryStaticcall' ? 'staticcall' : 'call';
    const shape = this.checkExternalCallShape(node, method, op, true);
    if (!shape) return undefined;
    if (op === 'call') this.currentWritesState = true;
    else this.currentReadsEnv = true;
    return {
      source: { kind: 'extCall', op, addr: recv, data: shape.data, value: shape.value, gas: shape.gas },
      types: [BOOL, BYTES],
    };
  }

  /** `let [ok, signer] = tryRecover(hash, sig)` -> [bool, address]: the never-reverting OZ ECDSA.tryRecover.
   *  A destructure-only builtin (like addr.tryCall). Returns the DestructureSource + component types. */
  private resolveTryRecover(node: ts.Expression): { source: DestructureSource; types: JethType[] } | undefined {
    if (!ts.isCallExpression(node) || !ts.isIdentifier(node.expression)) return undefined;
    if (node.expression.text !== 'tryRecover') return undefined;
    if (this.isVisibleLocal('tryRecover') || this.stateByName.has('tryRecover')) return undefined;
    if (node.arguments.length !== 2) {
      this.diags.error(node, 'JETH170', 'tryRecover(...) currently takes (hash: bytes32, sig: bytes)');
      return undefined;
    }
    const BYTES32: JethType = { kind: 'bytesN', size: 32 };
    const hash = this.checkExpr(node.arguments[0]!, BYTES32);
    const sig = this.checkExpr(node.arguments[1]!, this.bytesLiteralExpected(node.arguments[1]!));
    if (!hash || !sig) return undefined;
    if (hash.type.kind !== 'bytesN' || hash.type.size !== 32) {
      this.diags.error(
        node.arguments[0]!,
        'JETH171',
        `tryRecover(...) requires a bytes32 hash, got ${displayName(hash.type)}`,
      );
      return undefined;
    }
    if (sig.type.kind !== 'bytes') {
      this.diags.error(
        node.arguments[1]!,
        'JETH171',
        `tryRecover(...) requires a bytes signature, got ${displayName(sig.type)} (use bytes(...) for a string)`,
      );
      return undefined;
    }
    return { source: { kind: 'tryRecover', hash, sig }, types: [BOOL, ADDRESS] };
  }

  /** `const [fe, modulus] = pointEvaluation(versionedHash, z, y, commitment, proof)` -> [u256, u256]: the
   *  KZG point-evaluation precompile (0x0a). A destructure-only, env-reading (@view, NOT @pure) builtin. */
  private resolvePointEvaluation(node: ts.Expression): { source: DestructureSource; types: JethType[] } | undefined {
    if (!ts.isCallExpression(node) || !ts.isIdentifier(node.expression)) return undefined;
    if (node.expression.text !== 'pointEvaluation') return undefined;
    if (this.isVisibleLocal('pointEvaluation') || this.stateByName.has('pointEvaluation')) return undefined;
    // a STATICCALL reads the environment -> @view, not @pure (set even on a malformed call for consistency).
    this.currentReadsEnv = true;
    if (node.arguments.length !== 5) {
      this.diags.error(node, 'JETH170', 'pointEvaluation(...) takes (versionedHash, z, y, commitment, proof)');
      return undefined;
    }
    const BYTES32: JethType = { kind: 'bytesN', size: 32 };
    const versionedHash = this.checkExpr(node.arguments[0]!, BYTES32);
    const z = this.checkExpr(node.arguments[1]!, BYTES32);
    const y = this.checkExpr(node.arguments[2]!, BYTES32);
    const commitment = this.checkExpr(node.arguments[3]!, this.bytesLiteralExpected(node.arguments[3]!));
    const proof = this.checkExpr(node.arguments[4]!, this.bytesLiteralExpected(node.arguments[4]!));
    if (!versionedHash || !z || !y || !commitment || !proof) return undefined;
    for (const [x, i] of [
      [versionedHash, 0],
      [z, 1],
      [y, 2],
    ] as const) {
      if (x.type.kind !== 'bytesN' || x.type.size !== 32) {
        this.diags.error(
          node.arguments[i]!,
          'JETH171',
          `pointEvaluation(...) ${['versionedHash', 'z', 'y'][i]} must be bytes32, got ${displayName(x.type)}`,
        );
        return undefined;
      }
    }
    for (const [x, i] of [
      [commitment, 3],
      [proof, 4],
    ] as const) {
      if (x.type.kind !== 'bytes') {
        this.diags.error(
          node.arguments[i]!,
          'JETH171',
          `pointEvaluation(...) ${['', '', '', 'commitment', 'proof'][i]} must be bytes (length 48), got ${displayName(x.type)}`,
        );
        return undefined;
      }
    }
    return {
      source: { kind: 'pointEvaluation', versionedHash, z, y, commitment, proof },
      types: [U256, U256],
    };
  }

  /** `let [a, b] = addr.call/staticcall({..., decode: [T1, ...]})`: the in-object decode tuple form.
   *  The call's bytes result is wrapped in the abi.decode codec (same DestructureSource the tuple
   *  `<bytes>.decode([...])` sugar produces). Returns the source + component types, `'handled'` when the
   *  node IS an address call/staticcall but is misused (a precise diagnostic was emitted; stop), or
   *  undefined when the node is not an external call (let other handling decide). */
  private resolveCallDecodeTuple(
    node: ts.Expression,
  ): { source: DestructureSource; types: JethType[] } | 'handled' | undefined {
    if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) return undefined;
    const method = node.expression.name.text;
    if (method !== 'call' && method !== 'staticcall') return undefined;
    const recv = this.externalCallReceiver(node);
    if (!recv) return undefined; // not an address receiver -> not an external call
    const op: 'call' | 'staticcall' = method === 'staticcall' ? 'staticcall' : 'call';
    const shape = this.checkExternalCallShape(node, method, op, false);
    if (!shape) return 'handled'; // shape already emitted a precise diagnostic
    if (!shape.decode) {
      this.diags.error(
        node,
        'JETH323',
        `${method}(...) yields a single bytes value; to destructure, add a 'decode: [T1, ...]' tuple to the options (or bind the bytes with 'let x = ...')`,
      );
      return 'handled';
    }
    if (!shape.decode.tuple) {
      this.diags.error(
        node,
        'JETH323',
        `${method}(...) 'decode' is a single type, which yields one value; bind it with 'let x = ...' (use 'decode: [T1, ...]' to destructure)`,
      );
      return 'handled';
    }
    if (op === 'call') this.currentWritesState = true;
    else this.currentReadsEnv = true;
    const expr: Expr = {
      kind: 'extCall',
      type: BYTES,
      op,
      addr: recv,
      data: shape.data,
      value: shape.value,
      gas: shape.gas,
      checks: shape.checks,
    };
    return { source: { kind: 'abiDecode', data: expr, types: shape.decode.types }, types: shape.decode.types };
  }

  /** Recognize a tuple-form abi.decode source for `let [a, b] = abi.decode(data, [T1, ...])` (and the
   *  `<bytes>.decode([T1, ...])` sugar). Returns the DestructureSource + the component types, or
   *  undefined when the initializer is not a tuple abi.decode. */
  private resolveAbiDecodeTuple(node: ts.Expression): { source: DestructureSource; types: JethType[] } | undefined {
    if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) return undefined;
    const pa = node.expression;
    let dataNode: ts.Expression;
    let typeNode: ts.Expression;
    if (
      ts.isIdentifier(pa.expression) &&
      pa.expression.text === 'abi' &&
      !this.isVisibleLocal('abi') &&
      !this.stateByName.has('abi') &&
      pa.name.text === 'decode'
    ) {
      // abi.decode(data, [T1, ...])
      if (node.arguments.length !== 2 || !ts.isArrayLiteralExpression(node.arguments[1]!)) return undefined;
      dataNode = node.arguments[0]!;
      typeNode = node.arguments[1]!;
    } else if (
      pa.name.text === 'decode' &&
      node.arguments.length === 1 &&
      ts.isArrayLiteralExpression(node.arguments[0]!) &&
      this.isBytesValueExpr(pa.expression)
    ) {
      // <bytes>.decode([T1, ...])
      dataNode = pa.expression;
      typeNode = node.arguments[0]!;
    } else {
      return undefined;
    }
    const r = this.resolveAbiDecode(node, dataNode, typeNode);
    if (!r) return undefined;
    return { source: { kind: 'abiDecode', data: r.data, types: r.types }, types: r.types };
  }

  /** `revertWith(b)`: bubble raw bytes as the revert payload (revert(add(b,0x20), mload(b))). */
  private checkRevertWith(call: ts.CallExpression, out: Stmt[]): void {
    if (call.arguments.length !== 1) {
      this.diags.error(call, 'JETH312', 'revertWith(...) takes exactly one bytes argument');
      return;
    }
    const v = this.checkExpr(call.arguments[0]!, BYTES);
    if (!v) return;
    if (v.type.kind !== 'bytes') {
      this.diags.error(
        call.arguments[0]!,
        'JETH313',
        `revertWith(...) requires a bytes argument, got ${displayName(v.type)}`,
      );
      return;
    }
    out.push({ kind: 'revertWith', value: v });
  }

  // ---- events --------------------------------------------------------------

  private checkEmit(call: ts.CallExpression, out: Stmt[]): void {
    if (call.arguments.length !== 1) {
      this.diags.error(call, 'JETH145', 'emit(...) takes exactly one event-constructor argument');
      return;
    }
    const inner = call.arguments[0]!;
    if (!ts.isCallExpression(inner) || !ts.isIdentifier(inner.expression)) {
      this.diags.error(inner, 'JETH146', 'emit(...) argument must be an event constructor, e.g. emit(Transfer(a, b))');
      return;
    }
    const candidates = this.eventsByName.get(inner.expression.text);
    if (!candidates || candidates.length === 0) {
      this.diags.error(inner.expression, 'JETH147', `unknown event '${inner.expression.text}'`);
      return;
    }
    // Emitting a log is a STATE-MODIFYING effect (solc forbids it in view/pure, and a STATICCALL
    // reverts on LOG). Record it like a storage write so the transitive-purity fixpoint propagates
    // it through helpers: a @view/@pure/@read function that TRANSITIVELY emits is rejected too.
    this.currentWritesState = true;
    if (this.currentMutability === 'view' || this.currentMutability === 'pure') {
      this.diags.error(
        call,
        'JETH149',
        `cannot emit an event in a @${this.currentMutability} function (a log is a state change)`,
      );
    }
    // Resolve the overload: by argument count, then (for same-arity overloads) by a trial type-match.
    const byArity = candidates.filter((c) => c.params.length === inner.arguments.length);
    if (byArity.length === 0) {
      this.diags.error(
        inner,
        'JETH148',
        `event '${inner.expression.text}' has no overload taking ${inner.arguments.length} argument(s)`,
      );
      return;
    }
    let ev: EventIR;
    if (byArity.length === 1) ev = byArity[0]!;
    else {
      const viable = byArity.filter((c) => this.eventArgsMatch(inner, c));
      if (viable.length === 1) ev = viable[0]!;
      else {
        this.diags.error(
          inner,
          viable.length === 0 ? 'JETH148' : 'JETH901',
          viable.length === 0
            ? `no overload of event '${inner.expression.text}' matches the argument types`
            : `emit of '${inner.expression.text}' is ambiguous (matches ${viable.length} overloads)`,
        );
        return;
      }
    }
    const args: Expr[] = [];
    for (let i = 0; i < ev.params.length; i++) {
      const expected = ev.params[i]!.type;
      const a = this.checkExpr(inner.arguments[i]!, expected);
      if (!a) return;
      args.push(this.coerce(a, expected, inner.arguments[i]!));
    }
    out.push({ kind: 'emit', event: ev, args });
  }

  /** Trial type-check the emit args against an event overload's params, rolling back all side effects
   *  (diagnostics, effect flags) - used for same-arity event-overload resolution. */
  private eventArgsMatch(inner: ts.CallExpression, ev: EventIR): boolean {
    const diagLen = this.diags.items.length;
    const rs = this.currentReadsState,
      ws = this.currentWritesState,
      re = this.currentReadsEnv;
    let ok = true;
    for (let i = 0; i < ev.params.length; i++) {
      const a = this.checkExpr(inner.arguments[i]!, ev.params[i]!.type);
      if (!a) {
        ok = false;
        break;
      }
      this.coerce(a, ev.params[i]!.type, inner.arguments[i]!);
    }
    ok = ok && this.diags.items.length === diagLen;
    this.diags.items.length = diagLen;
    this.currentReadsState = rs;
    this.currentWritesState = ws;
    this.currentReadsEnv = re;
    return ok;
  }

  private checkLocalDecl(decl: ts.VariableDeclaration, out: Stmt[]): void {
    // `let [a, , c] = <multi-call | tuple>` (tuple destructuring declaration).
    if (ts.isArrayBindingPattern(decl.name)) {
      this.checkTupleDecl(decl, out);
      return;
    }
    if (!ts.isIdentifier(decl.name)) {
      this.diags.error(decl, 'JETH062', 'destructuring is not supported');
      return;
    }
    const declared = resolveType(decl.type, this.diags, this.structsByName);
    if (!decl.type) {
      this.diags.error(decl, 'JETH063', 'local variables require an explicit type annotation');
      return;
    }
    if (!declared) return;
    // A local whose type IS or CONTAINS a mapping is rejected (matches solc: "Uninitialized
    // mapping. Mappings cannot be created dynamically, you have to assign them from a state
    // variable."). Mappings are storage-only; a `let m: mapping<K,V>;` was previously inert
    // (no codegen) but is an over-acceptance. Reuse the same predicate as the ctor JETH247 gate.
    if (this.typeHasMapping(declared)) {
      this.diags.error(
        decl,
        'JETH340',
        `a ${displayName(declared)} cannot be a local variable - mappings are storage-only and cannot be created in memory`,
      );
      return;
    }
    // G9: a STATIC struct MEMORY local (let p: P = P(...)). The register holds a pointer to
    // an ABI-unpacked memory image (one word per leaf). It must be initialized from a
    // constructor P(...) or aliased from another memory struct (memAggregate); copies from a
    // storage/calldata source, and dynamic-field structs, are a later step.
    if (declared.kind === 'struct') {
      if (this.inCurrentScope(decl.name.text)) {
        this.diags.error(decl, 'JETH068', `redeclaration of '${decl.name.text}' in the same scope`);
        return;
      }
      if (!isStaticType(declared)) {
        // a DYNAMIC-field struct MEMORY local, scoped to value + bytes/string fields,
        // constructed inline (let d: D = D(x, str)). The image is a pointer-headed tuple
        // (value fields inline, bytes/string fields a [len][data] pointer), so reads and
        // `return d` reuse the dynamic-struct tuple encoder.
        if (this.isSupportedDynStructLocal(declared)) {
          if (!decl.initializer) {
            this.diags.error(
              decl,
              'JETH200',
              `a dynamic-field struct memory local must be initialized (e.g. let d: ${displayName(declared)} = ${(declared as JethType & { kind: 'struct' }).name}(...))`,
            );
            return;
          }
          const e = this.checkExpr(decl.initializer, declared);
          if (!e) return;
          // Allowed sources: a constructor D(...); a STORAGE struct (this.s -> structValue,
          // this.m[k] -> mapStorageValue, this.arr[i] -> structArrayElem, this.s.inner ->
          // placeRead) COPIED into a fresh image; a calldata struct param (cdDynStructValue)
          // decoded into a fresh image; or another dynamic-struct memory local (ALIAS).
          const okInit =
            e.kind === 'structNew' ||
            e.kind === 'structValue' ||
            e.kind === 'mapStorageValue' ||
            e.kind === 'structArrayElem' ||
            e.kind === 'cdDynStructValue' ||
            e.kind === 'memDynStructValue' ||
            e.kind === 'ternary' ||
            (e.kind === 'call' && e.type.kind === 'struct') ||
            (e.kind === 'placeRead' && e.type.kind === 'struct');
          if (!okInit) {
            this.diags.error(
              decl.initializer,
              'JETH200',
              `a dynamic-field struct memory local must be initialized from a constructor ${(declared as JethType & { kind: 'struct' }).name}(...), a storage struct (this.s / this.m[k] / this.arr[i]), a calldata struct parameter, or another struct local`,
            );
            return;
          }
          if (
            e.type.kind !== 'struct' ||
            (e.type as JethType & { kind: 'struct' }).name !== (declared as JethType & { kind: 'struct' }).name
          ) {
            this.diags.error(
              decl.initializer,
              'JETH085',
              `cannot initialize ${displayName(declared)} from ${displayName(e.type)}`,
            );
            return;
          }
          // a struct built FROM a calldata struct param whose dynamic-array field has NON-value
          // elements (T[][], string[], DynStruct[]) would need a recursive calldata-tail decode -
          // a later step. A dynamic VALUE-element array field (u256[], ...) decodes via abiEncFromCd
          // (per-element validation, byte-identical to solc's calldata->memory copy).
          if (
            e.kind === 'cdDynStructValue' &&
            (declared as JethType & { kind: 'struct' }).fields.some(
              (f) => f.type.kind === 'array' && f.type.length === undefined && !isStaticValueType(f.type.element),
            )
          ) {
            this.diags.error(
              decl.initializer,
              'JETH200',
              `constructing a memory struct with a dynamic-array field of non-value elements from a calldata struct parameter is not supported yet (use a constructor, a storage struct, or another struct local)`,
            );
            return;
          }
          this.declareLocal(decl.name.text, declared);
          this.memDynStructLocals.set(decl.name.text, declared);
          out.push({ kind: 'localDecl', name: decl.name.text, type: declared, init: e });
          return;
        }
        this.diags.error(
          decl,
          'JETH200',
          `local variables of dynamic struct type ${displayName(declared)} are not supported yet`,
        );
        return;
      }
      if (!decl.initializer) {
        // A STATIC struct memory local declared without an initializer (`let p: P;`) is
        // zero-initialized by solc. Lower it to a default-value constructor (the verified
        // structNew encoder over each field's zero default), which is byte-identical to
        // solc's `P memory p;`. (Dynamic-field structs returned above; they never reach here.)
        if (this.inCurrentScope(decl.name.text)) {
          this.diags.error(decl, 'JETH068', `redeclaration of '${decl.name.text}' in the same scope`);
          return;
        }
        const init = this.defaultStaticValue(declared);
        this.declareLocal(decl.name.text, declared);
        this.memAggregateLocals.set(decl.name.text, declared);
        out.push({ kind: 'localDecl', name: decl.name.text, type: declared, init });
        return;
      }
      const e = this.checkExpr(decl.initializer, declared);
      if (!e) return;
      // Allowed sources: a constructor StructName(...), another memory struct (ALIAS), a
      // struct-returning internal call, a whole STORAGE struct (this.s -> fresh COPY), or a
      // STATIC struct calldata param (q -> fresh COPY). The struct types must match.
      const okInit =
        e.kind === 'structNew' ||
        e.kind === 'memAggregate' ||
        (e.kind === 'call' && e.type.kind === 'struct') ||
        // Phase B / interface: a struct-returning external call (delegatecall library / interface call),
        // decoded from returndata into a memory image (the ABI struct decode yields a memAggregate-shaped
        // local). The struct type is validated by the checkExpr expected-type above.
        (e.kind === 'abiDecode' && e.type.kind === 'struct') ||
        e.kind === 'structValue' ||
        e.kind === 'cdAggregateValue' ||
        e.kind === 'ternary' ||
        e.kind === 'mapStorageValue' ||
        e.kind === 'structArrayElem';
      if (!okInit) {
        this.diags.error(
          decl.initializer,
          'JETH900',
          'a struct memory local must be initialized from a constructor StructName(...), another memory struct, a struct-returning internal call, a storage struct (this.s / this.m[k] / this.arr[i]), or a struct calldata parameter',
        );
        return;
      }
      if (
        (e.kind === 'structValue' ||
          e.kind === 'cdAggregateValue' ||
          e.kind === 'mapStorageValue' ||
          e.kind === 'structArrayElem') &&
        (e.type.kind !== 'struct' ||
          (e.type as JethType & { kind: 'struct' }).name !== (declared as JethType & { kind: 'struct' }).name)
      ) {
        this.diags.error(
          decl.initializer,
          'JETH085',
          `cannot initialize ${displayName(declared)} from ${displayName(e.type)}`,
        );
        return;
      }
      this.declareLocal(decl.name.text, declared);
      this.memAggregateLocals.set(decl.name.text, declared);
      out.push({ kind: 'localDecl', name: decl.name.text, type: declared, init: e });
      return;
    }
    // G9: a FIXED array of VALUE elements as a MEMORY local (let a: Arr<u256,3> = [...]). A
    // memAggregate (pointer to N words); a[i] reads/writes a word with a bounds check. Init from
    // an array literal, another fixed-array memory local (alias), a fixed-array calldata param,
    // or a storage fixed array (copy).
    if (declared.kind === 'array' && declared.length !== undefined && isStaticValueType(declared.element)) {
      if (this.inCurrentScope(decl.name.text)) {
        this.diags.error(decl, 'JETH068', `redeclaration of '${decl.name.text}' in the same scope`);
        return;
      }
      if (!decl.initializer) {
        this.diags.error(
          decl,
          'JETH200',
          `a fixed-array memory local must be initialized (e.g. let a: ${displayName(declared)} = [...])`,
        );
        return;
      }
      const e = this.checkExpr(decl.initializer, declared);
      if (!e) return;
      const fromStorage = e.kind === 'arrayValue' && e.arr.base.kind === 'fixedArray';
      const okInit =
        e.kind === 'arrayLit' ||
        e.kind === 'memAggregate' ||
        e.kind === 'cdAggregateValue' ||
        e.kind === 'ternary' ||
        e.kind === 'abiDecode' ||
        (e.kind === 'call' && e.type.kind === 'array') ||
        fromStorage;
      if (!okInit) {
        this.diags.error(
          decl.initializer,
          'JETH900',
          `a fixed-array memory local must be initialized from a literal, another memory fixed array, a fixed-array calldata parameter, or a storage fixed array`,
        );
        return;
      }
      this.declareLocal(decl.name.text, declared);
      this.memAggregateLocals.set(decl.name.text, declared);
      out.push({ kind: 'localDecl', name: decl.name.text, type: declared, init: e });
      return;
    }
    // A value-element dynamic-array local is a MEMORY array (a pointer to [len][elems]);
    // bytes/string and aggregate-element memory locals are a later step.
    if (declared.kind === 'array' && !(declared.length === undefined && isStaticValueType(declared.element))) {
      this.diags.error(
        decl,
        'JETH200',
        `local variables of type ${displayName(declared)} are not supported yet (memory: dynamic arrays of a value element)`,
      );
      return;
    }
    // G9: a bytes/string MEMORY local (let s: string = X). Its register holds a memory
    // [len][data] pointer materialized from the init source (calldata param / storage / another
    // memory string / a literal); reads route through the bytes/string codec (return, .length,
    // s[i], keccak, emit/error args). Must be initialized (Solidity has no null memory bytes).
    if (isBytesLike(declared)) {
      if (this.inCurrentScope(decl.name.text)) {
        this.diags.error(decl, 'JETH068', `redeclaration of '${decl.name.text}' in the same scope`);
        return;
      }
      if (!decl.initializer) {
        this.diags.error(decl, 'JETH200', `a ${displayName(declared)} memory local must be initialized`);
        return;
      }
      const e = this.checkExpr(decl.initializer, declared);
      if (!e) return;
      if (!typesEqual(e.type, declared)) {
        this.diags.error(
          decl.initializer,
          'JETH085',
          `cannot initialize ${displayName(declared)} from ${displayName(e.type)}`,
        );
        return;
      }
      this.declareLocal(decl.name.text, declared);
      this.memDynLocals.add(decl.name.text);
      out.push({ kind: 'localDecl', name: decl.name.text, type: declared, init: e });
      return;
    }
    if (this.inCurrentScope(decl.name.text)) {
      this.diags.error(decl, 'JETH068', `redeclaration of '${decl.name.text}' in the same scope`);
      return;
    }
    // a memory-array local must be initialized (Solidity has no null memory array).
    if (declared.kind === 'array' && !decl.initializer) {
      this.diags.error(decl, 'JETH200', 'a memory array local must be initialized (e.g. let xs: u256[] = [a, b])');
      return;
    }
    let init: Expr | undefined;
    if (decl.initializer) {
      const e = this.checkExpr(decl.initializer, declared);
      if (e) init = this.coerce(e, declared, decl.initializer);
    }
    this.declareLocal(decl.name.text, declared);
    if (declared.kind === 'array') this.memArrayLocals.add(decl.name.text);
    out.push({ kind: 'localDecl', name: decl.name.text, type: declared, init });
  }

  private checkAssignment(e: ts.BinaryExpression, out: Stmt[]): void {
    // `[a, , c] = <multi-call | tuple>` (tuple destructuring assignment to existing lvalues).
    if (ts.isArrayLiteralExpression(e.left)) {
      if (e.operatorToken.kind !== ts.SyntaxKind.EqualsToken) {
        this.diags.error(e.operatorToken, 'JETH064', 'compound assignment is not allowed on a tuple');
        return;
      }
      this.checkTupleAssign(e, out);
      return;
    }
    const target = this.checkLValue(e.left);
    if (!target) return;
    // A whole aggregate that contains a mapping cannot be assigned/copied (matches solc:
    // "types containing a mapping cannot be assigned"). Assigning its non-mapping fields
    // individually still works (their target type is a value, so this does not fire).
    if (this.typeHasMapping(target.type)) {
      this.diags.error(
        e.left,
        'JETH247',
        `cannot assign a whole ${displayName(target.type)} that contains a mapping (assign its non-mapping fields individually)`,
      );
      return;
    }
    const opKind = e.operatorToken.kind;

    if (opKind === ts.SyntaxKind.EqualsToken) {
      const rhs = this.checkExpr(e.right, target.type);
      if (!rhs) return;
      const value = this.coerce(rhs, target.type, e.right);
      // Constructing a whole STORAGE struct that has a dynamic-array field of NON-value elements
      // (T[][], string[], DynStruct[]) is a later step (writeStruct deep-copies only value-element
      // dynamic arrays); assign those fields individually. A dynamic VALUE-element array field
      // (u256[], address[], ...) is supported (writeStruct -> copyArrayValueIntoStorage).
      if (
        value.kind === 'structNew' &&
        (target.kind === 'state' ||
          target.kind === 'mapping' ||
          target.kind === 'place' ||
          target.kind === 'arrayElem') &&
        target.type.kind === 'struct' &&
        target.type.fields.some(
          (f) => f.type.kind === 'array' && f.type.length === undefined && !isStaticValueType(f.type.element),
        )
      ) {
        this.diags.error(
          e.right,
          'JETH200',
          `constructing a storage struct with a dynamic-array field of non-value elements is not supported yet (assign its fields individually: this.s.a = ...; this.s.xs.push(...))`,
        );
        return;
      }
      // Eval-order: solc evaluates the RHS before the LHS location. The value-type and bytes/string
      // element paths reorder correctly in codegen, but the WHOLE-AGGREGATE element write path
      // (recs[i] = P(...), dd[i] = [...]) does not, so a side-effecting index/key would run before the
      // RHS aggregate's constructor args and miscompile. Reject it (bind the index to a const first),
      // consistent with the JETH331 guard already applied to ++/-- and compound assignments.
      if (target.type.kind === 'struct' || target.type.kind === 'array') {
        const keyImpure = this.impureLValueKey(e.left);
        if (keyImpure) {
          this.diags.error(
            keyImpure,
            'JETH331',
            `assigning a whole ${displayName(target.type)} to an element with a side-effecting index/key would evaluate the index before the value (solc evaluates the value first); bind the index to a const first`,
          );
          return;
        }
      }
      out.push({ kind: 'assign', target, value });
      return;
    }

    // compound: desugar `lhs op= rhs` into `lhs = lhs op rhs`
    const binOp = this.compoundToBinOp(opKind);
    if (!binOp) {
      this.diags.error(e.operatorToken, 'JETH064', `unsupported assignment operator`);
      return;
    }
    const keyImpure = this.impureLValueKey(e.left);
    if (keyImpure) {
      this.diags.error(
        keyImpure,
        'JETH331',
        `a compound assignment to an element with a side-effecting index/key would evaluate the index twice (solc evaluates it once); bind the index to a const first`,
      );
      return;
    }
    const left = this.lvalueAsExpr(target);
    const rhs = this.checkExpr(e.right, target.type);
    if (!rhs) return;
    const combined = this.buildBinary(binOp, left, rhs, e);
    if (!combined) return;
    const value = this.coerce(combined, target.type, e);
    out.push({ kind: 'assign', target, value });
  }

  /** Assignment as a value-producing expression: (x = v), (x += v), chained x = y = a.
   *  Mirrors checkAssignment but returns an Expr that yields the assigned (LHS-typed)
   *  value, byte-identical to Solidity. Restricted to static value-typed lvalues (the
   *  common case); aggregate/bytes/string lvalues keep statement-only assignment. */
  private checkAssignmentExpr(e: ts.BinaryExpression): Expr | undefined {
    const target = this.checkLValue(e.left);
    if (!target) return undefined;
    if (!isStaticValueType(target.type)) {
      this.diags.error(
        e,
        'JETH075',
        `assignment in expression position is supported only for value types, not ${displayName(target.type)}`,
      );
      return undefined;
    }
    const opKind = e.operatorToken.kind;
    if (opKind === ts.SyntaxKind.EqualsToken) {
      const rhs = this.checkExpr(e.right, target.type);
      if (!rhs) return undefined;
      const value = this.coerce(rhs, target.type, e.right);
      return { kind: 'assignExpr', type: target.type, target, value };
    }
    const binOp = this.compoundToBinOp(opKind);
    if (!binOp) {
      this.diags.error(e.operatorToken, 'JETH064', `unsupported assignment operator`);
      return undefined;
    }
    const keyImpure = this.impureLValueKey(e.left);
    if (keyImpure) {
      this.diags.error(
        keyImpure,
        'JETH331',
        `a compound assignment to an element with a side-effecting index/key would evaluate the index twice (solc evaluates it once); bind the index to a const first`,
      );
      return undefined;
    }
    const left = this.lvalueAsExpr(target);
    const rhs = this.checkExpr(e.right, target.type);
    if (!rhs) return undefined;
    const combined = this.buildBinary(binOp, left, rhs, e);
    if (!combined) return undefined;
    const value = this.coerce(combined, target.type, e);
    return { kind: 'assignExpr', type: target.type, target, value };
  }

  /** Resolve a bare-identifier call `f(args)` to a contract function as an INTERNAL call
   *  (Solidity semantics: same contract context, no message-call). Returns a `call` Expr
   *  (its type is the callee's return type; void only allowed when asStatement). First cut:
   *  value-typed params and a value/void return (aggregate/bytes/string params and returns,
   *  and multi-value returns, are cleanly gated until aggregate memory locals land). */
  // F3: a default parameter value must be a self-contained compile-time constant, so filling it
  // at any internal call site is deterministic and side-effect-free (no caller-scope dependency).
  private isConstDefault(node: ts.Expression): boolean {
    if (ts.isParenthesizedExpression(node)) return this.isConstDefault(node.expression);
    if (ts.isBigIntLiteral(node) || ts.isNumericLiteral(node)) return true;
    if (node.kind === ts.SyntaxKind.TrueKeyword || node.kind === ts.SyntaxKind.FalseKeyword) return true;
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.MinusToken)
      return this.isConstDefault(node.operand);
    // type(T).max / type(T).min
    if (ts.isPropertyAccessExpression(node) && (node.name.text === 'max' || node.name.text === 'min'))
      return this.isConstDefault(node.expression);
    // an enum member constant `Color.Red` is a compile-time constant.
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isIdentifier(node.expression) &&
      this.isEnumName(node.expression.text)
    )
      return true;
    // a value cast / builtin over constants: address(0n), u8(255n), bytes4(0x..n), payable(0n), type(u256), Color(0n)
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      const c = node.expression.text;
      if (c === 'address' || c === 'payable' || c === 'type' || resolvePrimitiveName(c) || this.isEnumName(c)) {
        return node.arguments.every((a) => this.isConstDefault(a) || (c === 'type' && ts.isIdentifier(a)));
      }
    }
    return false;
  }

  // True when a single object-literal argument is a NAMED call `f({ p: v, ... })`: every member is
  // `name: value` (or shorthand) and every name is a parameter name. Otherwise it is an ordinary
  // positional argument (e.g. a struct-literal value for a single struct param).
  private looksLikeNamedArgs(obj: ts.ObjectLiteralExpression, params: { name: string }[]): boolean {
    if (obj.properties.length === 0) return false;
    const names = new Set(params.map((p) => p.name));
    for (const p of obj.properties) {
      if (!(ts.isPropertyAssignment(p) || ts.isShorthandPropertyAssignment(p))) return false;
      if (!ts.isIdentifier(p.name) || !names.has(p.name.text)) return false;
    }
    return true;
  }

  /** Resolve an internal-call argument list to one TS expression per parameter, honoring named-call
   *  form `f({p: v})` and trailing defaults. Returns undefined (with a diagnostic) on arity / name
   *  errors. Default fills reuse the callee signature's (constant) initializer node verbatim. */
  private resolveCallArgs(node: ts.CallExpression, callee: RawFunction, name: string): ts.Expression[] | undefined {
    const params = callee.params;
    const defaults = callee.defaults ?? params.map(() => undefined);
    const provided = node.arguments;
    if (
      provided.length === 1 &&
      ts.isObjectLiteralExpression(provided[0]!) &&
      this.looksLikeNamedArgs(provided[0] as ts.ObjectLiteralExpression, params)
    ) {
      const byName = new Map<string, ts.Expression>();
      for (const p of (provided[0] as ts.ObjectLiteralExpression).properties) {
        const key = (p.name as ts.Identifier).text;
        if (byName.has(key)) {
          this.diags.error(p.name!, 'JETH253', `duplicate named argument '${key}' in call to '${name}'`);
          return undefined;
        }
        byName.set(key, ts.isPropertyAssignment(p) ? p.initializer : (p.name as ts.Expression));
      }
      const out: ts.Expression[] = [];
      for (let i = 0; i < params.length; i++) {
        const nm = params[i]!.name;
        if (byName.has(nm)) out.push(byName.get(nm)!);
        else if (defaults[i]) out.push(defaults[i]!);
        else {
          this.diags.error(node, 'JETH254', `named call to '${name}' is missing argument '${nm}' (no default)`);
          return undefined;
        }
      }
      return out;
    }
    if (provided.length > params.length) {
      this.diags.error(
        node,
        'JETH148',
        `'${name}' expects at most ${params.length} argument(s), got ${provided.length}`,
      );
      return undefined;
    }
    const out: ts.Expression[] = [];
    for (let i = 0; i < params.length; i++) {
      if (i < provided.length) out.push(provided[i]!);
      else if (defaults[i]) out.push(defaults[i]!);
      else {
        this.diags.error(node, 'JETH148', `'${name}' is missing argument '${params[i]!.name}' (no default)`);
        return undefined;
      }
    }
    return out;
  }

  /** A function's unique call-graph key: its bare name when unique, else `name__ovN` (an overload) or
   *  a generic mangled name. Distinct from `name` (the source name, shared by overloads). */
  private fkey(rf: RawFunction): string {
    return rf.key ?? rf.name;
  }

  /** Resolve a (possibly overloaded) internal call `name(...)` to a single callee. One candidate ->
   *  that one. Several (overloading by arity or parameter types, like solc) -> filter by callable
   *  arity (accounting for F3 defaults / named-arg form), then by which candidate's parameter types
   *  ALL the arguments fit. Emits JETH148 (no match) / JETH901 (ambiguous). */
  private resolveOverload(node: ts.CallExpression, name: string): RawFunction | undefined {
    const candidates = this.candidatesByName.get(name);
    if (!candidates || candidates.length === 0) return this.funcsByName.get(name); // generic mangled name / none
    if (candidates.length === 1) return candidates[0];
    const applicable = candidates.filter((c) => this.overloadApplicable(node, c));
    if (applicable.length === 0) {
      this.diags.error(node, 'JETH148', `no overload of '${name}' accepts this number of arguments`);
      return undefined;
    }
    if (applicable.length === 1) return applicable[0];
    const viable = applicable.filter((c) => this.overloadArgsMatch(node, c));
    if (viable.length === 1) return viable[0];
    if (viable.length === 0) {
      this.diags.error(node, 'JETH148', `no overload of '${name}' matches the argument types`);
      return undefined;
    }
    this.diags.error(node, 'JETH901', `call to '${name}' is ambiguous (matches ${viable.length} overloads)`);
    return undefined;
  }

  /** Is the call's argument SHAPE (arity / named form) callable on this candidate (F3 defaults aware)? */
  private overloadApplicable(node: ts.CallExpression, c: RawFunction): boolean {
    const params = c.params;
    const defaults = c.defaults ?? params.map(() => undefined);
    const provided = node.arguments;
    if (
      provided.length === 1 &&
      ts.isObjectLiteralExpression(provided[0]!) &&
      this.looksLikeNamedArgs(provided[0] as ts.ObjectLiteralExpression, params)
    ) {
      const keys = new Set<string>();
      for (const p of (provided[0] as ts.ObjectLiteralExpression).properties) keys.add((p.name as ts.Identifier).text);
      return params.every((p, i) => keys.has(p.name) || !!defaults[i]);
    }
    if (provided.length > params.length) return false;
    for (let i = provided.length; i < params.length; i++) if (!defaults[i]) return false;
    return true;
  }

  /** Do ALL the call's arguments fit this candidate's parameter types? A TRIAL type-check with every
   *  side effect (diagnostics, effect flags, callee set) rolled back, so resolution never pollutes the
   *  real analysis - the chosen overload's args are re-checked normally afterwards. */
  private overloadArgsMatch(node: ts.CallExpression, c: RawFunction): boolean {
    const diagLen = this.diags.items.length;
    const rs = this.currentReadsState,
      ws = this.currentWritesState,
      re = this.currentReadsEnv;
    const savedCallees = this.currentCallees;
    this.currentCallees = new Set();
    let ok = true;
    const argNodes = this.resolveCallArgs(node, c, c.name);
    if (!argNodes) ok = false;
    else
      for (let i = 0; i < c.params.length; i++) {
        const a = this.checkExpr(argNodes[i]!, c.params[i]!.type);
        if (!a) {
          ok = false;
          break;
        }
        this.coerce(a, c.params[i]!.type, argNodes[i]!);
      }
    ok = ok && this.diags.items.length === diagLen; // a clean check leaves no new diagnostics
    this.diags.items.length = diagLen; // discard trial diagnostics
    this.currentReadsState = rs;
    this.currentWritesState = ws;
    this.currentReadsEnv = re;
    this.currentCallees = savedCallees;
    return ok;
  }

  /** Inheritance: resolve `super.f(args)` to the next implementation in the linearization. Inside a
   *  function defined by `Cx`, super.f resolves to the FIRST contract AFTER Cx (in the deployed
   *  contract's full linearization) that DEFINES f - exactly solc's MRO super order. A super outside
   *  an inherited function, or to an unimplemented next-in-line, is rejected cleanly. The resolved
   *  base version is passed forced into checkInternalCall (which handles arg checking + IR). */
  private checkSuperCall(
    node: ts.CallExpression,
    name: string,
    asStatement: boolean,
  ): (Expr & { kind: 'call' }) | undefined {
    const here = this.currentDefiningContract;
    if (here === undefined) {
      this.diags.error(node, 'JETH382', `'super' is only valid inside an inherited contract function`);
      return undefined;
    }
    const hereIdx = this.linOrder.indexOf(here);
    // Among all override chains for source name `name`, pick the one whose params the args fit AND
    // that contains `here`; then take the first entry strictly after `here`. Most signatures have a
    // single chain; an overloaded `f` across the chain disambiguates by arg arity/types.
    const candidates: { chain: { contract: string; key: string; rf: RawFunction }[]; nextIdx: number }[] = [];
    for (const chain of this.overrideChains.values()) {
      if (chain.length === 0 || chain[0]!.rf.name !== name) continue;
      const pos = chain.findIndex((e) => e.contract === here);
      // `here` must appear in this chain (it defines this signature) for super to climb past it.
      if (pos < 0) {
        // `here` may not itself define f (it inherits f) yet still call super.f: then super means the
        // first version after `here` in the LINEARIZATION. Use the first chain entry whose contract is
        // strictly more-base than `here`.
        const ni = chain.findIndex((e) => this.linOrder.indexOf(e.contract) > hereIdx);
        if (ni >= 0) candidates.push({ chain, nextIdx: ni });
        continue;
      }
      if (pos + 1 < chain.length) candidates.push({ chain, nextIdx: pos + 1 });
    }
    if (candidates.length === 0) {
      this.diags.error(
        node,
        'JETH381',
        `super.${name}(...) has no implementation after '${here}' in the inheritance chain (the base method is abstract/unimplemented or does not exist)`,
      );
      return undefined;
    }
    // Disambiguate by which candidate's target params the args fit (overloaded super).
    const viable = candidates.filter(
      (c) =>
        this.overloadApplicable(node, c.chain[c.nextIdx]!.rf) && this.overloadArgsMatch(node, c.chain[c.nextIdx]!.rf),
    );
    const chosen = viable.length === 1 ? viable[0]! : candidates.length === 1 ? candidates[0]! : viable[0];
    if (!chosen) {
      this.diags.error(node, 'JETH381', `super.${name}(...) does not match any base implementation's parameters`);
      return undefined;
    }
    const target = chosen.chain[chosen.nextIdx]!.rf;
    return this.checkInternalCall(node, name, asStatement, target);
  }

  private checkInternalCall(
    node: ts.CallExpression,
    name: string,
    asStatement: boolean,
    forcedCallee?: RawFunction,
  ): (Expr & { kind: 'call' }) | undefined {
    // Inheritance: super.f() supplies the resolved base version directly (no name-based overload
    // resolution); otherwise resolve the (possibly overloaded) callee from the source name.
    const callee = forcedCallee ?? this.resolveOverload(node, name);
    if (!callee) return undefined;
    if (callee.visibility === 'external') {
      this.diags.error(
        node,
        'JETH240',
        `cannot internally call @external function '${name}' (only internal/private/public functions are callable by name)`,
      );
      return undefined;
    }
    if (callee.nonReentrant) {
      // The transient mutex is emitted on the EXTERNAL entry only; an internal call would bypass
      // it (or, if it did not, falsely trip the guard). Forbid it, matching how a Solidity
      // nonReentrant function is not meant to be re-entered through an internal call.
      this.diags.error(
        node,
        'JETH262',
        `cannot internally call @nonReentrant function '${name}' (the reentrancy guard protects the external entry only)`,
      );
      return undefined;
    }
    if (callee.returnTypes) {
      this.diags.error(
        node,
        'JETH241',
        `internal call to a multi-value-return function '${name}' is not supported yet`,
      );
      return undefined;
    }
    // An aggregate (struct / fixed-array / dynamic value-array / bytes / string) param/return is
    // passed BY MEMORY REFERENCE on an internal call - supported only when the callee is
    // @internal/@private (its params are pure memory pointers). A @public function's params are
    // ABI-decoded from calldata in its userfn_ body, so an internal call passing a memory pointer
    // would mismatch; that dual calldata+memory case stays gated (a clean JETH242 rejection).
    const aggOK = callee.visibility === 'internal' || callee.visibility === 'private';
    // An @internal/@private function passes an aggregate BY MEMORY REFERENCE: a static struct, a
    // dynamic value-element array (u256[]/u64[]/address[]...), or bytes/string. A memory-source arg
    // ALIASES (a callee mutation is visible to the caller, like solc); a storage/calldata/literal
    // source is COPIED to fresh memory (the codegen materializes it).
    const isMemByRef = (t: JethType): boolean =>
      (t.kind === 'struct' && isStaticType(t)) ||
      (t.kind === 'array' && t.length !== undefined && isStaticType(t)) || // a static fixed array Arr<T,N>
      (t.kind === 'array' && t.length === undefined && isStaticValueType(t.element)) ||
      isBytesLike(t);
    const paramSupported = (t: JethType): boolean =>
      isStaticValueType(t) || (aggOK && (isMemByRef(t) || this.isSupportedDynStructLocal(t)));
    for (const p of callee.params) {
      if (paramSupported(p.type)) continue;
      const hint =
        isMemByRef(p.type) && !aggOK ? ' (aggregate params require the callee to be @internal or @private)' : '';
      this.diags.error(
        node,
        'JETH242',
        `internal call to '${name}' is not supported yet (parameter type ${displayName(p.type)} is not supported${hint})`,
      );
      return undefined;
    }
    const rt = callee.returnType;
    const returnSupported =
      rt.kind === 'void' || isStaticValueType(rt) || (aggOK && (isMemByRef(rt) || this.isSupportedDynStructLocal(rt)));
    if (!returnSupported) {
      const hint =
        isMemByRef(rt) && !aggOK ? ' (aggregate returns require the callee to be @internal or @private)' : '';
      this.diags.error(
        node,
        'JETH243',
        `internal call to '${name}' is not supported yet (return type ${displayName(rt)} is not supported${hint})`,
      );
      return undefined;
    }
    if (!asStatement && callee.returnType.kind === 'void') {
      this.diags.error(node, 'JETH244', `'${name}' returns void and cannot be used as a value`);
      return undefined;
    }
    const argNodes = this.resolveCallArgs(node, callee, name);
    if (!argNodes) return undefined;
    const args: Expr[] = [];
    for (let i = 0; i < callee.params.length; i++) {
      const pt = callee.params[i]!.type;
      const a = this.checkExpr(argNodes[i]!, pt);
      if (!a) return undefined;
      if (pt.kind === 'struct') {
        // a memory-struct argument (passed by reference): the argument must be the same struct.
        if (a.type.kind !== 'struct' || a.type.name !== pt.name) {
          this.diags.error(
            argNodes[i]!,
            'JETH085',
            `argument ${i + 1} of '${name}' expects ${displayName(pt)}, got ${displayName(a.type)}`,
          );
          return undefined;
        }
        args.push(a);
      } else {
        args.push(this.coerce(a, pt, argNodes[i]!));
      }
    }
    const key = this.fkey(callee);
    this.currentCallees.add(key);
    this.internallyCalled.add(key);
    return { kind: 'call', type: callee.returnType, fn: key, args };
  }

  // ---- Phase A: library call resolution (L.f(args) and attached x.f(args)) ----

  /** Type-check `expr` purely to learn its type, rolling back ALL side effects (diagnostics, effect
   *  flags, callee set). Used to peek a `.f(...)` receiver's type for attachment lookup WITHOUT
   *  committing to it (the real check happens in buildLibraryCall). Returns the type or undefined. */
  private trialExprType(expr: ts.Expression): JethType | undefined {
    const diagLen = this.diags.items.length;
    const rs = this.currentReadsState,
      ws = this.currentWritesState,
      re = this.currentReadsEnv;
    const savedCallees = this.currentCallees;
    this.currentCallees = new Set();
    const r = this.checkExpr(expr);
    this.diags.items.length = diagLen;
    this.currentReadsState = rs;
    this.currentWritesState = ws;
    this.currentReadsEnv = re;
    this.currentCallees = savedCallees;
    return r?.type;
  }

  /** `<funcref>.selector` -> the 4-byte ABI selector of an EXTERNAL/PUBLIC function `fnName`, as a
   *  compile-time bytes4 literal (the selector left-aligned in the high 4 bytes, identical to
   *  abi.encodeWithSelector's literal). Returns undefined after a diagnostic when `fnName` names a
   *  function that is internal/private or has multiple overloads (an ambiguous selector); returns
   *  undefined with NO diagnostic when `fnName` is not a known function (caller falls through). */
  private functionSelectorOf(node: ts.Node, fnName: string): Expr | undefined {
    const overloads = this.candidatesByName.get(fnName);
    if (!overloads || overloads.length === 0) return undefined; // not a function name: caller falls through
    const exposed = overloads.filter((f) => f.visibility === 'external' || f.visibility === 'public');
    if (exposed.length === 0) {
      this.diags.error(
        node,
        'JETH074',
        `.selector requires an external or public function ('${fnName}' is internal/private and has no ABI selector)`,
      );
      return undefined;
    }
    if (exposed.length > 1) {
      this.diags.error(
        node,
        'JETH074',
        `.selector on overloaded function '${fnName}' is ambiguous (it has ${exposed.length} external/public overloads)`,
      );
      return undefined;
    }
    const f = exposed[0]!;
    const sig = functionSignature(
      f.name,
      f.params.map((p) => p.type),
    );
    const selector = functionSelector(sig);
    return { kind: 'literalInt', type: { kind: 'bytesN', size: 4 }, value: BigInt('0x' + selector) << 224n };
  }

  /** Resolve a qualified library call `L.f(args)` (the receiver is NOT prepended). `node.arguments`
   *  is the full positional/named argument list, so this delegates to the SAME internal-call path
   *  via a forced callee resolved against L's overload set - making it byte-identical to a contract
   *  internal call. Returns the call Expr, or undefined (after a diagnostic). */
  private resolveQualifiedLibraryCall(
    node: ts.CallExpression,
    libName: string,
    fnName: string,
    asStatement: boolean,
  ): Expr | undefined {
    const candidates = this.libraryByName.get(libName)!;
    const callee = this.resolveLibraryOverload(node, candidates, `${libName}.${fnName}`, fnName);
    if (callee === 'unknown') {
      this.diags.error(node, 'JETH392', `@library '${libName}' has no function '${fnName}'`);
      return undefined;
    }
    if (!callee) return undefined; // an ambiguity/no-match diagnostic was already emitted
    // Phase B: an @external library function is a DELEGATECALL (not inlined); route through the shared
    // arg-check + extCall builder. node.arguments is the full positional arg list (no receiver prepend).
    if (callee.libraryExternal) return this.buildLibraryCall(node, callee, [...node.arguments], asStatement);
    return this.checkInternalCall(node, `${libName}.${fnName}`, asStatement, callee);
  }

  /** Resolve an attached library call `x.f(args)` == `L.f(x, ...args)`. The receiver `x` is the
   *  first argument; the candidate set is the @using attachment list for (typeof x, f). Returns the
   *  call Expr (byte-identical to the internal call `L.f(x, ...args)`), 'no-match' if no attached
   *  function fits (so the caller falls through to non-library member handling), or undefined after a
   *  diagnostic (an ambiguous attachment). */
  /** Names of the BUILT-IN members of the receiver type `t` that a call `x.f(...)` could dispatch to.
   *  Used to detect a same-name collision with an `@using(L)` attached function: solc makes the member
   *  access AMBIGUOUS in that case ("Member \"f\" not unique after argument-dependent lookup ...") and
   *  rejects, where JETH would otherwise silently let the built-in win. Mirrors solc's member sets for
   *  the types `@using` can attach to (arrays, bytes/string, address). A lib fn attached to a DIFFERENT
   *  type than the receiver is not a collision (this set is per-receiver-type). */
  private builtinMemberOfReceiver(t: JethType, fnName: string): boolean {
    if (t.kind === 'array') {
      // every array (fixed or dynamic) has the built-in `.length`; a dynamic array also has push/pop.
      // (Verified vs solc 0.8.35: a same-name @using fn on uint256[]/uint256[N]/uint256[] storage is
      // "Member ... not unique after argument-dependent lookup".)
      return fnName === 'length' || (t.length === undefined && (fnName === 'push' || fnName === 'pop'));
    }
    if (t.kind === 'address') {
      // address built-in MEMBERS that solc treats as a collision: balance/code/codehash. NOT call/
      // staticcall/transfer/send - solc 0.8.35 ACCEPTS a same-name @using fn for those on a plain
      // `address` receiver (the library function wins; no ambiguity), so they are not gated here.
      return fnName === 'balance' || fnName === 'code' || fnName === 'codehash';
    }
    // bytes/string: `.length` only. `.concat`/`.slice` are JETH SURFACE sugar (solc has no such member;
    // `data[start:end]` is the calldata-slice OPERATOR), so an attached `slice`/`concat` is NOT a solc
    // collision (verified: solc resolves `data.slice(...)` to the attached library function).
    if (isBytesLike(t)) return fnName === 'length';
    return false;
  }

  /** Detect an `@using(L)` attached-function name that collides with a BUILT-IN member of the SAME
   *  receiver type (e.g. a lib `length(u256[])` vs the built-in `.length`). solc rejects the member
   *  access as ambiguous; JETH otherwise lets the built-in silently win. Fires only when an applicable
   *  attachment exists AND the name is a built-in of the receiver type; emits JETH341 and returns true
   *  (handled). Checked at the dispatch sites BEFORE the built-in handlers so the built-in cannot win. */
  private attachedBuiltinCollision(
    node: ts.CallExpression | ts.PropertyAccessExpression,
    receiver: ts.Expression,
    recvType: JethType,
    fnName: string,
  ): boolean {
    if (!this.builtinMemberOfReceiver(recvType, fnName)) return false;
    const list = this.libraryAttachments.get(`${canonicalName(recvType)}#${fnName}`);
    if (!list || list.length === 0) return false;
    // a PROPERTY member access (`a.length`, `addr.balance`) has only the receiver as its argument; a
    // CALL (`a.length()`) appends its args. solc rejects BOTH forms when the name collides.
    const argExprs = ts.isCallExpression(node) ? [receiver, ...node.arguments] : [receiver];
    if (!list.some((c) => this.libraryArgsApplicable(argExprs, c))) return false;
    this.diags.error(
      node,
      'JETH341',
      `member '.${fnName}' on ${displayName(recvType)} is ambiguous: it is both a built-in member and an @using attached library function (solc rejects this collision; rename the library function or call it qualified as L.${fnName}(${receiver.getText()}, ...))`,
    );
    return true;
  }

  private resolveAttachedLibraryCall(
    node: ts.CallExpression,
    receiver: ts.Expression,
    recvType: JethType,
    fnName: string,
    asStatement: boolean,
  ): Expr | undefined | 'no-match' {
    const list = this.libraryAttachments.get(`${canonicalName(recvType)}#${fnName}`);
    if (!list || list.length === 0) return 'no-match';
    // Disambiguate by the FULL synthetic arg list (receiver ++ node.arguments) - an overloaded
    // attached `f` for the same receiver type T resolves by the remaining args' arity/types.
    const argExprs = [receiver, ...node.arguments];
    const applicable = list.filter((c) => this.libraryArgsApplicable(argExprs, c));
    if (applicable.length === 0) {
      // Receiver type matched but no overload accepts these args. If there is a SINGLE attached fn,
      // surface its arity/type mismatch (matches an internal-call diagnostic); otherwise fall through.
      if (list.length === 1) return this.buildLibraryCall(node, list[0]!, argExprs, asStatement);
      return 'no-match';
    }
    let callee = applicable[0]!;
    if (applicable.length > 1) {
      const viable = applicable.filter((c) => this.libraryArgsMatch(argExprs, c));
      if (viable.length === 1) callee = viable[0]!;
      else {
        // Two @using libraries (or two overloads) attach `f` for T with indistinguishable args.
        this.diags.error(
          node,
          'JETH393',
          `attached call '.${fnName}(...)' on ${displayName(recvType)} is ambiguous (${applicable.length} @using library functions match)`,
        );
        return undefined;
      }
    }
    return this.buildLibraryCall(node, callee, argExprs, asStatement);
  }

  /** Resolve an overload of a library function `name` from `candidates` against `node.arguments`
   *  (positional/named). Returns the single matching RawFunction, undefined (a diagnostic was
   *  emitted for ambiguity / no-arg-match), or 'unknown' when the candidate set is empty. */
  private resolveLibraryOverload(
    node: ts.CallExpression,
    candidates: RawFunction[],
    qualified: string,
    fnName: string,
  ): RawFunction | undefined | 'unknown' {
    const named = candidates.filter((c) => c.name === `${qualified}`);
    if (named.length === 0) {
      // candidates are the WHOLE library; filter by the bare function name.
      const byName = candidates.filter((c) => c.name.endsWith(`.${fnName}`));
      if (byName.length === 0) return 'unknown';
      return this.pickLibraryOverload(node, byName, qualified);
    }
    return this.pickLibraryOverload(node, named, qualified);
  }

  private pickLibraryOverload(
    node: ts.CallExpression,
    list: RawFunction[],
    qualified: string,
  ): RawFunction | undefined {
    if (list.length === 1) return list[0]!;
    const applicable = list.filter((c) => this.overloadApplicable(node, c));
    if (applicable.length === 0) {
      this.diags.error(node, 'JETH148', `no overload of '${qualified}' accepts this number of arguments`);
      return undefined;
    }
    if (applicable.length === 1) return applicable[0]!;
    const viable = applicable.filter((c) => this.overloadArgsMatch(node, c));
    if (viable.length === 1) return viable[0]!;
    if (viable.length === 0) {
      this.diags.error(node, 'JETH148', `no overload of '${qualified}' matches the argument types`);
      return undefined;
    }
    this.diags.error(node, 'JETH901', `call to '${qualified}' is ambiguous (matches ${viable.length} overloads)`);
    return undefined;
  }

  /** Is the (already receiver-prepended) arg list `argExprs` callable on candidate `c` by arity?
   *  Library attachment never uses the named-arg object form (the receiver is positional), so this
   *  is a plain arity check, F3-default aware. */
  private libraryArgsApplicable(argExprs: ts.Expression[], c: RawFunction): boolean {
    const params = c.params;
    const defaults = c.defaults ?? params.map(() => undefined);
    if (argExprs.length > params.length) return false;
    for (let i = argExprs.length; i < params.length; i++) if (!defaults[i]) return false;
    return true;
  }

  /** Do ALL the (receiver-prepended) args fit candidate `c`'s parameter types? A TRIAL type-check
   *  with every side effect rolled back (mirrors overloadArgsMatch but over an explicit arg list). */
  private libraryArgsMatch(argExprs: ts.Expression[], c: RawFunction): boolean {
    if (!this.libraryArgsApplicable(argExprs, c)) return false;
    const diagLen = this.diags.items.length;
    const rs = this.currentReadsState,
      ws = this.currentWritesState,
      re = this.currentReadsEnv;
    const savedCallees = this.currentCallees;
    this.currentCallees = new Set();
    let ok = true;
    for (let i = 0; i < c.params.length; i++) {
      const node = i < argExprs.length ? argExprs[i]! : (c.defaults![i] as ts.Expression);
      const a = this.checkExpr(node, c.params[i]!.type);
      if (!a) {
        ok = false;
        break;
      }
      this.coerce(a, c.params[i]!.type, node);
    }
    ok = ok && this.diags.items.length === diagLen;
    this.diags.items.length = diagLen;
    this.currentReadsState = rs;
    this.currentWritesState = ws;
    this.currentReadsEnv = re;
    this.currentCallees = savedCallees;
    return ok;
  }

  /** Build a library call to `callee` from the explicit (receiver-prepended) arg expressions. This
   *  mirrors checkInternalCall's gate + arg-check + IR construction but consumes an explicit arg list
   *  (so the attached `x.f(args)` form can prepend the receiver). The result IR is the SAME
   *  `{kind:'call', fn:<key>, args}` an internal call produces - so codegen needs no new path. */
  private buildLibraryCall(
    node: ts.CallExpression,
    callee: RawFunction,
    argExprs: ts.Expression[],
    asStatement: boolean,
  ): Expr | undefined {
    // A library function is never @payable/@nonReentrant (gated at collection). An @external library
    // function is a DELEGATECALL (Phase B); a bare one is inlined (Phase A). Both share the same param/
    // return ABI-support gates and arg type-checking; only the produced IR differs.
    if (callee.returnTypes) {
      this.diags.error(
        node,
        'JETH241',
        `call to a multi-value-return library function '${callee.name}' is not supported yet`,
      );
      return undefined;
    }
    const isMemByRef = (t: JethType): boolean =>
      (t.kind === 'struct' && isStaticType(t)) ||
      (t.kind === 'array' && t.length !== undefined && isStaticType(t)) ||
      (t.kind === 'array' && t.length === undefined && isStaticValueType(t.element)) ||
      isBytesLike(t);
    const paramSupported = (t: JethType): boolean =>
      isStaticValueType(t) || isMemByRef(t) || this.isSupportedDynStructLocal(t);
    for (const p of callee.params) {
      if (paramSupported(p.type)) continue;
      this.diags.error(
        node,
        'JETH242',
        `call to library function '${callee.name}' is not supported yet (parameter type ${displayName(p.type)} is not supported)`,
      );
      return undefined;
    }
    const rt = callee.returnType;
    const returnSupported =
      rt.kind === 'void' || isStaticValueType(rt) || isMemByRef(rt) || this.isSupportedDynStructLocal(rt);
    if (!returnSupported) {
      this.diags.error(
        node,
        'JETH243',
        `call to library function '${callee.name}' is not supported yet (return type ${displayName(rt)} is not supported)`,
      );
      return undefined;
    }
    if (!asStatement && rt.kind === 'void') {
      this.diags.error(node, 'JETH244', `library function '${callee.name}' returns void and cannot be used as a value`);
      return undefined;
    }
    // Resolve arg expressions (positional ++ trailing defaults), then type-check each against its
    // parameter type. A wrong arity here is a real call error (the receiver/overload already matched).
    const params = callee.params;
    const defaults = callee.defaults ?? params.map(() => undefined);
    if (argExprs.length > params.length) {
      this.diags.error(
        node,
        'JETH148',
        `'${callee.name}' expects at most ${params.length} argument(s), got ${argExprs.length}`,
      );
      return undefined;
    }
    const argNodes: ts.Expression[] = [];
    for (let i = 0; i < params.length; i++) {
      if (i < argExprs.length) argNodes.push(argExprs[i]!);
      else if (defaults[i]) argNodes.push(defaults[i]!);
      else {
        this.diags.error(node, 'JETH148', `'${callee.name}' is missing argument '${params[i]!.name}' (no default)`);
        return undefined;
      }
    }
    const args: Expr[] = [];
    for (let i = 0; i < params.length; i++) {
      const pt = params[i]!.type;
      const a = this.checkExpr(argNodes[i]!, pt);
      if (!a) return undefined;
      if (pt.kind === 'struct') {
        if (a.type.kind !== 'struct' || a.type.name !== pt.name) {
          this.diags.error(
            argNodes[i]!,
            'JETH085',
            `argument ${i + 1} of '${callee.name}' expects ${displayName(pt)}, got ${displayName(a.type)}`,
          );
          return undefined;
        }
        args.push(a);
      } else {
        args.push(this.coerce(a, pt, argNodes[i]!));
      }
    }
    if (callee.libraryExternal) {
      // Phase B: a DELEGATECALL to the library's own deployed object (linked at deploy time). Do NOT add
      // the callee to internallyCalled (it is not inlined into this contract): it is emitted as a
      // selector-dispatched entry in the LIBRARY object. Build (selector ++ abi.encode(args)) and
      // delegatecall, bubbling the callee's revert bytes verbatim; the returndata is abi.decoded.
      return this.buildLibraryExtCall(callee, args, asStatement);
    }
    const key = this.fkey(callee);
    this.currentCallees.add(key);
    this.internallyCalled.add(key);
    return { kind: 'call', type: rt, fn: key, args };
  }

  /** Phase B: build the delegatecall expression for an @external library function. `args` are the
   *  already type-checked + coerced argument Exprs (receiver-prepended for an attached call). Encodes
   *  (selector ++ abi.encode(args)) to memory, `delegatecall(gas(), linkersymbol("L"), ...)`, bubbles the
   *  raw revert on failure, and abi.decodes the returndata into the declared return type. For a void
   *  return the bare extCall is the (statement) expression. Marks the library as externally referenced. */
  private buildLibraryExtCall(callee: RawFunction, args: Expr[], asStatement: boolean): Expr {
    const lib = callee.libraryName!;
    this.referencedExternalLibraries.add(lib);
    const bareName = callee.name.slice(lib.length + 1); // strip the `L.` qualifier for the ABI signature
    const signature = functionSignature(
      bareName,
      callee.params.map((p) => p.type),
    );
    const selector = functionSelector(signature);
    const selExpr: Expr = {
      kind: 'literalInt',
      type: { kind: 'bytesN', size: 4 },
      value: BigInt('0x' + selector) << 224n,
    };
    const data: Expr = { kind: 'abiEncode', type: BYTES, packed: false, args, selector: selExpr };
    // The CALL's effect mirrors the library function's declared mutability (a JETH library function
    // cannot touch contract storage anyway - JETH394 - so it is effectively pure/view): a non-view fn is
    // a state-writing effect; a view fn reads state; a @pure fn has no effect (calling a pure library
    // function from a @pure function is allowed, matching solc). An @read fn is provisionally view.
    // Effect: add the callee to the purity CALL GRAPH (currentCallees) so the transitive-purity fixpoint
    // propagates the library function's REAL (post-fixpoint) mutability to this caller - exactly like an
    // internal call - instead of guessing at the call site (a bare external lib fn's @read mutability is
    // not resolved yet). It is NOT added to internallyCalled: it is delegatecalled, never inlined here.
    // A declared NONPAYABLE (not @read/@view/@pure) library function is a state-modifying call from the
    // caller's view (solc rejects a @view caller delegatecalling a non-view library fn), so force a write.
    this.currentCallees.add(this.fkey(callee));
    if (!callee.inferRead && callee.mutability === 'nonpayable') this.currentWritesState = true;
    const call: Expr & { kind: 'extCall' } = {
      kind: 'extCall',
      type: BYTES,
      op: 'delegatecall',
      lib,
      data,
      checks: [],
      bubble: true,
    };
    const rt = callee.returnType;
    if (rt.kind === 'void') return call; // a statement: run the delegatecall, discard the (empty) returndata
    void asStatement;
    return { kind: 'abiDecode', type: rt, data: call };
  }

  /** A return component that a tuple destructuring can bind to a fresh memory local: any value
   *  type, plus a non-value the memory-local machinery already supports (bytes/string, a dynamic
   *  value-array, or a STATIC struct). A DYNAMIC struct's local layout (memDynStructLocals,
   *  pointer-headed) differs from the flat ABI return blob, so it stays rejected (safe). */
  private destructurableComponent(t: JethType): boolean {
    if (isStaticValueType(t)) return true;
    if (isBytesLike(t)) return true;
    if (t.kind === 'array' && t.length === undefined && isStaticValueType(t.element)) return true;
    if (t.kind === 'struct' && isStaticType(t)) return true;
    return false;
  }

  /** Resolve a multi-value internal call `f(...)` / `this.f(...)` as a tuple destructuring
   *  source: the callee must be internal/private with `n` VALUE return components and value
   *  params. Returns {fn, args, types} or undefined (with a diagnostic). */
  private resolveTupleCall(
    node: ts.CallExpression,
    name: string,
    n: number,
  ): { fn: string; args: Expr[]; types: JethType[] } | undefined {
    const callee = this.resolveOverload(node, name);
    if (!callee) return undefined;
    if (callee.visibility === 'external') {
      this.diags.error(node, 'JETH240', `cannot internally call @external function '${name}'`);
      return undefined;
    }
    if (!callee.returnTypes || callee.returnTypes.length < 2) {
      this.diags.error(node, 'JETH066', `'${name}' does not return a tuple; cannot destructure`);
      return undefined;
    }
    if (callee.returnTypes.length !== n) {
      this.diags.error(
        node,
        'JETH066',
        `destructuring expects ${n} value(s) but '${name}' returns ${callee.returnTypes.length}`,
      );
      return undefined;
    }
    for (const t of callee.returnTypes) {
      if (!this.destructurableComponent(t)) {
        this.diags.error(
          node,
          'JETH243',
          `tuple destructuring of a non-value return component (${displayName(t)}) is not supported yet`,
        );
        return undefined;
      }
    }
    for (const p of callee.params) {
      if (!isStaticValueType(p.type)) {
        this.diags.error(
          node,
          'JETH242',
          `internal call to '${name}' is not supported yet (parameter type ${displayName(p.type)})`,
        );
        return undefined;
      }
    }
    const argNodes = this.resolveCallArgs(node, callee, name);
    if (!argNodes) return undefined;
    const args: Expr[] = [];
    for (let i = 0; i < callee.params.length; i++) {
      const a = this.checkExpr(argNodes[i]!, callee.params[i]!.type);
      if (!a) return undefined;
      args.push(this.coerce(a, callee.params[i]!.type, argNodes[i]!));
    }
    const key = this.fkey(callee);
    this.currentCallees.add(key);
    this.internallyCalled.add(key);
    return { fn: key, args, types: callee.returnTypes };
  }

  /** The internal-callee name of `f(...)` / `this.f(...)`, if it resolves to a known function. */
  private tupleCallName(node: ts.Expression): string | undefined {
    if (!ts.isCallExpression(node)) return undefined;
    if (ts.isIdentifier(node.expression) && this.funcsByName.has(node.expression.text)) return node.expression.text;
    if (
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.expression.kind === ts.SyntaxKind.ThisKeyword &&
      this.funcsByName.has(node.expression.name.text)
    )
      return node.expression.name.text;
    return undefined;
  }

  /** `let [a, , c] = <multi-call | [e1, e2, ...]>`: declare a new local per non-skipped element
   *  (type inferred from the source component), skipping omitted slots. Value components only. */
  private checkTupleDecl(decl: ts.VariableDeclaration, out: Stmt[]): void {
    const pat = decl.name as ts.ArrayBindingPattern;
    const n = pat.elements.length;
    if (!decl.initializer) {
      this.diags.error(decl, 'JETH066', 'a tuple destructuring declaration requires an initializer');
      return;
    }
    // Phase 6: `let [a, b] = IFoo(addr).method(args)` where the method has a >=2-component tuple return:
    // decode the call's bytes returndata into N components (same abi.decode path as a tuple addr.call).
    const ifaceCall = this.resolveInterfaceCall(decl.initializer);
    if (ifaceCall === 'handled') return; // recognized interface call, already diagnosed
    if (ifaceCall) {
      if (!ifaceCall.returnTypes) {
        this.diags.error(
          decl.name,
          'JETH356',
          ifaceCall.returnType.kind === 'void'
            ? 'this interface method returns void and cannot be destructured (call it as a statement)'
            : 'this interface method returns a single value; bind it with `let x = ...`, not a destructuring',
        );
        return;
      }
      const rts = ifaceCall.returnTypes;
      if (rts.length !== n) {
        this.diags.error(
          decl.name,
          'JETH356',
          `this interface method returns ${rts.length} value(s), expected ${n} name(s)`,
        );
        return;
      }
      this.bindDestructure(pat, n, rts, { kind: 'abiDecode', data: ifaceCall.call, types: rts }, out);
      return;
    }
    // `let [ok, signer] = tryRecover(...)` / `const [fe, modulus] = pointEvaluation(...)`: destructure-only
    // builtins (mirror addr.tryCall). Recognized before the generic call/abi.decode resolvers.
    const tryRecover = this.resolveTryRecover(decl.initializer);
    if (tryRecover) {
      if (n !== 2) {
        this.diags.error(
          decl.name,
          'JETH066',
          `tryRecover destructuring expects exactly 2 names [ok, signer], got ${n}`,
        );
        return;
      }
      this.bindDestructure(pat, n, tryRecover.types, tryRecover.source, out);
      return;
    }
    const pointEval = this.resolvePointEvaluation(decl.initializer);
    if (pointEval) {
      if (n !== 2) {
        this.diags.error(
          decl.name,
          'JETH066',
          `pointEvaluation destructuring expects exactly 2 names [fe, modulus], got ${n}`,
        );
        return;
      }
      this.bindDestructure(pat, n, pointEval.types, pointEval.source, out);
      return;
    }
    const callName = this.tupleCallName(decl.initializer);
    const tryCall = this.resolveTryCall(decl.initializer);
    const callDecode = tryCall ? undefined : this.resolveCallDecodeTuple(decl.initializer);
    if (callDecode === 'handled') return; // recognized address call/staticcall, already diagnosed
    const abiDecodeTuple = tryCall || callDecode ? undefined : this.resolveAbiDecodeTuple(decl.initializer);
    let types: JethType[];
    let source: DestructureSource;
    if (callDecode) {
      // `let [a, b] = addr.call({..., decode: [T1, T2]})`: decode the call's bytes result (same binding
      // path as the abi.decode tuple form below - each component lands in its own register / mem image).
      if (callDecode.types.length !== n) {
        this.diags.error(
          decl.name,
          'JETH066',
          `call decode tuple has ${callDecode.types.length} type(s), expected ${n} name(s)`,
        );
        return;
      }
      types = callDecode.types;
      source = callDecode.source;
    } else if (abiDecodeTuple) {
      // `let [a, b] = abi.decode(data, [T1, T2])`: each component is decoded into its own register
      // (value -> a word, bytes/string/array/struct -> a memory image pointer), bound below.
      if (abiDecodeTuple.types.length !== n) {
        this.diags.error(
          decl.name,
          'JETH066',
          `abi.decode tuple has ${abiDecodeTuple.types.length} type(s), expected ${n} name(s)`,
        );
        return;
      }
      types = abiDecodeTuple.types;
      source = abiDecodeTuple.source;
    } else if (tryCall) {
      // `let [ok, ret] = addr.tryCall/tryStaticcall({...})` -> [bool, bytes].
      if (n !== 2) {
        this.diags.error(
          decl.name,
          'JETH314',
          `tryCall/tryStaticcall destructuring expects exactly 2 names [ok, ret], got ${n}`,
        );
        return;
      }
      types = tryCall.types;
      source = tryCall.source;
    } else if (callName) {
      const r = this.resolveTupleCall(decl.initializer as ts.CallExpression, callName, n);
      if (!r) return;
      types = r.types;
      source = { kind: 'call', fn: r.fn, args: r.args };
    } else if (ts.isArrayLiteralExpression(decl.initializer)) {
      if (decl.initializer.elements.length !== n) {
        this.diags.error(
          decl.initializer,
          'JETH066',
          `tuple has ${decl.initializer.elements.length} value(s), expected ${n}`,
        );
        return;
      }
      const values: Expr[] = [];
      types = [];
      for (const el of decl.initializer.elements) {
        const v = this.checkExpr(el);
        if (!v) return;
        if (!isStaticValueType(v.type)) {
          this.diags.error(
            el,
            'JETH066',
            `tuple destructuring of a non-value component (${displayName(v.type)}) is not supported yet`,
          );
          return;
        }
        values.push(v);
        types.push(v.type);
      }
      source = { kind: 'tuple', values };
    } else {
      this.diags.error(
        decl.initializer,
        'JETH066',
        'tuple destructuring requires a multi-value call or a tuple literal on the right',
      );
      return;
    }
    this.bindDestructure(pat, n, types, source, out);
  }

  /** Declare a fresh local per non-skipped binding element of a tuple destructuring and emit the
   *  tupleDecl. A non-value component binds a memory local in its kind's side-table (so later reads
   *  resolve through the right codec). Shared by the internal-call, abi.decode, tryCall, and
   *  interface-call tuple forms. */
  private bindDestructure(
    pat: ts.ArrayBindingPattern,
    n: number,
    types: JethType[],
    source: DestructureSource,
    out: Stmt[],
  ): void {
    const names: (string | null)[] = [];
    for (let i = 0; i < n; i++) {
      const el = pat.elements[i]!;
      if (ts.isOmittedExpression(el)) {
        names.push(null);
        continue;
      }
      if (!ts.isBindingElement(el) || !ts.isIdentifier(el.name)) {
        this.diags.error(el, 'JETH062', 'only simple names are allowed in a tuple destructuring');
        return;
      }
      const nm = el.name.text;
      if (this.inCurrentScope(nm)) {
        this.diags.error(el, 'JETH068', `redeclaration of '${nm}' in the same scope`);
        return;
      }
      this.declareLocal(nm, types[i]!);
      // a non-value component binds a fresh MEMORY local that aliases the returned reference;
      // register it in the side-table its kind uses so later reads (return / .length / [i] / .f)
      // resolve through the right codec (mirrors a `let x: T = ...` localDecl).
      const ct = types[i]!;
      if (isBytesLike(ct)) this.memDynLocals.add(nm);
      // a dynamic value-element array binds a [len][elems] memory pointer (memArrayLocals); a static
      // fixed array Arr<T,N> binds a flat ABI image (memAggregateLocals, like a struct). These extra
      // cases only fire for the abi.decode tuple form - the tryCall source yields only a bytes/bool pair.
      else if (ct.kind === 'array' && ct.length === undefined) this.memArrayLocals.add(nm);
      else if (ct.kind === 'array') this.memAggregateLocals.set(nm, ct);
      else if (ct.kind === 'struct' && isDynamicType(ct)) this.memDynStructLocals.set(nm, ct);
      else if (ct.kind === 'struct') this.memAggregateLocals.set(nm, ct);
      names.push(nm);
    }
    out.push({ kind: 'tupleDecl', names, types, source });
  }

  /** `[a, , c] = <multi-call | [e1, e2, ...]>`: assign each non-skipped value to an existing
   *  value lvalue (omitted slots discard the component). RHS is fully evaluated before any store. */
  private checkTupleAssign(e: ts.BinaryExpression, out: Stmt[]): void {
    const lhs = e.left as ts.ArrayLiteralExpression;
    const n = lhs.elements.length;
    const targets: (LValue | null)[] = [];
    for (const el of lhs.elements) {
      if (ts.isOmittedExpression(el)) {
        targets.push(null);
        continue;
      }
      const lv = this.checkLValue(el);
      if (!lv) return;
      if (!isStaticValueType(lv.type)) {
        this.diags.error(
          el,
          'JETH066',
          `tuple assignment to a non-value target (${displayName(lv.type)}) is not supported yet`,
        );
        return;
      }
      targets.push(lv);
    }
    const callName = this.tupleCallName(e.right);
    let source: { kind: 'call'; fn: string; args: Expr[] } | { kind: 'tuple'; values: Expr[] };
    if (callName) {
      const r = this.resolveTupleCall(e.right as ts.CallExpression, callName, n);
      if (!r) return;
      for (let i = 0; i < n; i++) {
        const tgt = targets[i];
        if (tgt && !typesEqual(r.types[i]!, tgt.type) && !isImplicitWiden(r.types[i]!, tgt.type)) {
          this.diags.error(
            lhs.elements[i]!,
            'JETH085',
            `cannot assign ${displayName(r.types[i]!)} to ${displayName(tgt.type)}`,
          );
          return;
        }
      }
      source = { kind: 'call', fn: r.fn, args: r.args };
    } else if (ts.isArrayLiteralExpression(e.right)) {
      if (e.right.elements.length !== n) {
        this.diags.error(e.right, 'JETH066', `tuple has ${e.right.elements.length} value(s), expected ${n}`);
        return;
      }
      const values: Expr[] = [];
      for (let i = 0; i < n; i++) {
        const el = e.right.elements[i]!;
        const tgt = targets[i];
        const v = this.checkExpr(el, tgt?.type);
        if (!v) return;
        values.push(tgt ? this.coerce(v, tgt.type, el) : v);
      }
      source = { kind: 'tuple', values };
    } else {
      this.diags.error(
        e.right,
        'JETH066',
        'tuple assignment requires a multi-value call or a tuple literal on the right',
      );
      return;
    }
    out.push({ kind: 'tupleAssign', targets, source });
  }

  /** Word offset (and type) of a struct field within the ABI-unpacked memory image, for a
   *  memory-aggregate local (G9). Returns undefined if the field is absent. */
  private memFieldOffset(
    structType: JethType & { kind: 'struct' },
    fieldName: string,
  ): { wordOffset: number; type: JethType } | undefined {
    let w = 0;
    for (const f of structType.fields) {
      if (f.name === fieldName) return { wordOffset: w, type: f.type };
      w += abiHeadWords(f.type);
    }
    return undefined;
  }

  /** The root memory-aggregate local name of a property-access chain `p.f1...fn`, else undefined. */
  private memChainRoot(node: ts.Expression): string | undefined {
    if (ts.isIdentifier(node)) return this.memAggregateLocals.has(node.text) ? node.text : undefined;
    if (ts.isPropertyAccessExpression(node)) return this.memChainRoot(node.expression);
    return undefined;
  }

  /** Resolve `p.f1.f2...fn` rooted at a memory-aggregate (struct) local into the final field's
   *  {local, wordOffset, type}, descending through nested STRUCT fields (word offsets sum). The
   *  final field type may be a struct or a value (callers decide what they accept). */
  private resolveMemFieldChain(
    node: ts.PropertyAccessExpression,
  ): { local: string; wordOffset: number; type: JethType } | undefined {
    let base: { local: string; wordOffset: number; type: JethType };
    if (ts.isIdentifier(node.expression)) {
      const st = this.memAggregateLocals.get(node.expression.text);
      if (!st || st.kind !== 'struct') return undefined;
      base = { local: node.expression.text, wordOffset: 0, type: st };
    } else if (ts.isPropertyAccessExpression(node.expression)) {
      const parent = this.resolveMemFieldChain(node.expression);
      if (!parent) return undefined;
      base = parent;
    } else {
      return undefined;
    }
    if (base.type.kind !== 'struct') {
      this.diags.error(node, 'JETH210', `'${node.name.text}' is not a field of ${displayName(base.type)}`);
      return undefined;
    }
    const fo = this.memFieldOffset(base.type, node.name.text);
    if (!fo) {
      this.diags.error(node, 'JETH210', `struct '${base.type.name}' has no field '${node.name.text}'`);
      return undefined;
    }
    return { local: base.local, wordOffset: base.wordOffset + fo.wordOffset, type: fo.type };
  }

  /** A `p.f1...fn` read/write on a memory struct local where the FINAL field is a VALUE type:
   *  maps to a memory load/store at the accumulated word offset. Non-value final fields are gated. */
  private resolveMemAggregateField(
    node: ts.PropertyAccessExpression,
  ): { local: string; wordOffset: number; type: JethType } | undefined {
    const r = this.resolveMemFieldChain(node);
    if (!r) return undefined;
    if (!isStaticValueType(r.type)) {
      this.diags.error(
        node,
        'JETH245',
        `accessing a non-value field of a memory struct is not supported yet (read/write a value field)`,
      );
      return undefined;
    }
    return r;
  }

  /** A constructor param type that JETH supports (JETH302). Value types decode to a single head word;
   *  the aggregate/dynamic shapes are exactly those an @internal/@private function passes BY MEMORY
   *  REFERENCE - a static struct, a static fixed array Arr<T,N>, a dynamic value-element array T[],
   *  bytes/string, or a supported dynamic-field struct - so the ctor decodes each from the appended
   *  creation args (abiDecFromMem) and the body reads it from memory, byte-identical to solc. A type
   *  containing a mapping (JETH247) and a defaulted param (JETH304) are rejected before this. */
  private ctorParamSupported(t: JethType): boolean {
    return isStaticValueType(t) || this.isMemByRefAggregate(t) || this.isSupportedDynStructLocal(t);
  }

  /** The aggregate shapes a constructor decodes into a MEMORY image and binds like an @internal memory-
   *  reference param (mirrors the isMemByRef closure in checkInternalCall): a static struct, a static
   *  fixed array Arr<T,N>, a dynamic value-element array T[], or bytes/string. */
  private isMemByRefAggregate(t: JethType): boolean {
    return (
      (t.kind === 'struct' && isStaticType(t)) ||
      (t.kind === 'array' && t.length !== undefined && isStaticType(t)) ||
      (t.kind === 'array' && t.length === undefined && isStaticValueType(t.element)) ||
      isBytesLike(t)
    );
  }

  /** Register an aggregate/dynamic constructor parameter into the memory-local maps, exactly as
   *  checkFunction does for an @internal/@private function's by-reference params, so a body read of
   *  p[i] / p.x / p.length / return p resolves to a memory place. A value-type param needs no entry. */
  private registerAggregateCtorParam(name: string, t: JethType): void {
    if (t.kind === 'struct' && isStaticType(t)) this.memAggregateLocals.set(name, t);
    else if (t.kind === 'array' && t.length !== undefined && isStaticType(t)) this.memAggregateLocals.set(name, t);
    else if (t.kind === 'array' && t.length === undefined && isStaticValueType(t.element)) this.memArrayLocals.add(name);
    else if (isBytesLike(t)) this.memDynLocals.add(name);
    else if (this.isSupportedDynStructLocal(t)) this.memDynStructLocals.set(name, t);
  }

  /** JETH322: register an aggregate/dynamic @modifier parameter into the memory-local maps, so a body
   *  read p.length / p[i] / p.x (and a pass-through to the wrapped userfn) resolves to the materialized
   *  memory place. A value-type param needs no entry (it binds as a plain Yul register via localDecl). */
  private registerAggregateModifierParam(name: string, t: JethType): void {
    if (isStaticValueType(t)) return;
    this.registerAggregateCtorParam(name, t);
  }

  /** A dynamic-field struct is supported as a MEMORY local only when every field is a value
   *  type or bytes/string (no static-aggregate or nested-struct fields). This keeps the image
   *  one head word per field (value inline, bytes/string a pointer), matching the tuple head. */
  private isSupportedDynStructLocal(t: JethType): boolean {
    if (t.kind !== 'struct' || !isDynamicType(t)) return false;
    // every field must be a value type (inline head word), bytes/string (head pointer to [len][data]),
    // or a dynamic value-element array (head pointer to [len][elems]). Static-array / nested-struct /
    // string[] / T[][] fields stay gated.
    return t.fields.every(
      (f) =>
        isStaticValueType(f.type) ||
        isBytesLike(f.type) ||
        (f.type.kind === 'array' && f.type.length === undefined && isStaticValueType(f.type.element)),
    );
  }

  /** Resolve `d.field` where `d` is a DYNAMIC-field struct memory local into its head-word
   *  offset and field. Only a direct identifier base is supported (no nesting in scope). */
  private memDynStructField(
    node: ts.PropertyAccessExpression,
  ): { local: string; headWord: number; field: StructField } | undefined {
    if (!ts.isIdentifier(node.expression)) return undefined;
    const st = this.memDynStructLocals.get(node.expression.text);
    if (!st || st.kind !== 'struct') return undefined;
    const idx = st.fields.findIndex((f) => f.name === node.name.text);
    if (idx < 0) {
      this.diags.error(node, 'JETH210', `struct '${st.name}' has no field '${node.name.text}'`);
      return undefined;
    }
    const headWord = st.fields
      .slice(0, idx)
      .reduce((n, ff) => n + (isDynamicType(ff.type) ? 1 : abiHeadWords(ff.type)), 0);
    return { local: node.expression.text, headWord, field: st.fields[idx]! };
  }

  // ---- lvalues -------------------------------------------------------------

  private checkLValue(node: ts.Expression): LValue | undefined {
    // `d.x = v` on a DYNAMIC-field struct memory local: a VALUE field is a plain memory store
    // at the head word. A bytes/string field write would re-point the head at a new blob (size
    // may change); that is gated for now (construction + reads + return are supported).
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isIdentifier(node.expression) &&
      this.memDynStructLocals.has(node.expression.text)
    ) {
      const mf = this.memDynStructField(node);
      if (!mf) return undefined;
      // a bytes/string field write re-points the head word at a freshly-materialized blob.
      if (isBytesLike(mf.field.type)) {
        return { kind: 'memDynField', type: mf.field.type, local: mf.local, wordOffset: mf.headWord };
      }
      // writing a whole dynamic-array field of a memory struct (re-pointing the head word) is a later
      // step; element writes (p.xs[i] = v) are gated separately.
      if (mf.field.type.kind === 'array' && mf.field.type.length === undefined) {
        this.diags.error(node, 'JETH200', `writing a dynamic-array field of a memory struct is not supported yet`);
        return undefined;
      }
      return { kind: 'memField', type: mf.field.type, local: mf.local, wordOffset: mf.headWord };
    }
    // G9: `p.x = v` / `p.inner.x = v` on a memory-aggregate (struct) local -> a memory store.
    if (ts.isPropertyAccessExpression(node) && this.memChainRoot(node)) {
      const mf = this.resolveMemAggregateField(node);
      if (!mf) return undefined;
      return { kind: 'memField', type: mf.type, local: mf.local, wordOffset: mf.wordOffset };
    }
    // G9: `a[i] = v` on a fixed-array MEMORY local (value element) -> a bounds-checked store.
    if (ts.isElementAccessExpression(node) && ts.isIdentifier(node.expression) && node.argumentExpression) {
      const at = this.memAggregateLocals.get(node.expression.text);
      if (at && at.kind === 'array' && at.length !== undefined) {
        const index = this.checkExpr(node.argumentExpression, U256);
        if (!index) return undefined;
        const idx = this.coerce(index, U256, node.argumentExpression);
        if (!this.checkMemElemBound(idx, at.length, node.argumentExpression)) return undefined;
        return { kind: 'memElem', type: at.element, local: node.expression.text, index: idx, length: at.length };
      }
    }
    // G9: `p.a[i] = v` where a is a fixed-array VALUE field of a memory struct local.
    if (
      ts.isElementAccessExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.argumentExpression &&
      this.memChainRoot(node.expression)
    ) {
      const fld = this.resolveMemFieldChain(node.expression);
      if (fld && fld.type.kind === 'array' && fld.type.length !== undefined && isStaticValueType(fld.type.element)) {
        const index = this.checkExpr(node.argumentExpression, U256);
        if (!index) return undefined;
        const idx = this.coerce(index, U256, node.argumentExpression);
        if (!this.checkMemElemBound(idx, fld.type.length, node.argumentExpression)) return undefined;
        return {
          kind: 'memElem',
          type: fld.type.element,
          local: fld.local,
          index: idx,
          length: fld.type.length,
          wordOffset: fld.wordOffset,
        };
      }
    }
    // this.b[i] = <bytes1>: byte assignment into a STORAGE `bytes` (RMW the containing slot/word).
    // The bytes may be a direct state var OR reached through a struct field / mapping value /
    // bytes[] or Arr<bytes,N> element. (string is not element-assignable in solc.) The bytes
    // LOCATION is resolved first; its slot is computed at codegen like the whole-value assignment.
    if (
      ts.isElementAccessExpression(node) &&
      node.argumentExpression &&
      (ts.isPropertyAccessExpression(node.expression) || ts.isElementAccessExpression(node.expression))
    ) {
      const loc = this.bytesLocation(node.expression);
      if (loc) {
        const idx = this.checkExpr(node.argumentExpression, U256);
        if (!idx) return undefined;
        this.currentWritesState = true;
        return { kind: 'byteIndexStore', type: BYTES1, loc, index: this.coerce(idx, U256, node.argumentExpression) };
      }
    }
    // nested storage place: this.s.f, this.pts[i].x, this.m[k].f, this.m[r][c]
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const acc = this.resolveAccess(node);
      if (acc) {
        if (!acc.result) return undefined;
        // Assigning a whole FIXED-array leaf at depth (this.g3[i][j] = arr) is a later
        // step (no fixed-array value source to copy from); reading it works.
        if (acc.result.finalType.kind === 'array') {
          this.diags.error(
            node,
            'JETH226',
            'assigning a whole fixed-array element at depth is a later step (assign its elements)',
          );
          return undefined;
        }
        this.currentWritesState = true;
        // A bytes/string leaf (storage dynamic-struct field) write goes through the
        // storage bytes/string codec (storeStrMem, overwrite-clearing old tail),
        // not a packed-word sstore.
        if (isBytesLike(acc.result.finalType)) {
          return { kind: 'dynPlace', type: acc.result.finalType, path: acc.result.path };
        }
        return { kind: 'place', type: acc.result.finalType, path: acc.result.path };
      }
      // a dynamic-struct calldata param is read-only.
      if (ts.isPropertyAccessExpression(node)) {
        const dyn = this.resolveCdDynStruct(node);
        if (dyn) {
          if (dyn.result)
            this.diags.error(node, 'JETH214', 'a calldata parameter is read-only (cannot assign to its fields)');
          return undefined;
        }
      }
      // a struct / fixed-array calldata param is read-only.
      const cd = this.resolveCalldataPlace(node);
      if (cd) {
        if (cd.result)
          this.diags.error(node, 'JETH214', 'a calldata parameter is read-only (cannot assign to its fields/elements)');
        return undefined;
      }
    }

    // this.struct.field = v
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.expression.kind === ts.SyntaxKind.ThisKeyword
    ) {
      const sv = this.stateByName.get(node.expression.name.text);
      if (sv && sv.type.kind === 'struct') {
        const f = sv.type.fields.find((ff) => ff.name === node.name.text);
        if (!f) {
          this.diags.error(node, 'JETH210', `struct '${sv.type.name}' has no field '${node.name.text}'`);
          return undefined;
        }
        // this.d.s = <bytes/string>: a dynamic field of a storage dynamic struct.
        // The field header lives at sv.slot + f.slot (a normal storage bytes/string);
        // a single-field path folds to that constant slot at codegen.
        if (isBytesLike(f.type)) {
          this.currentWritesState = true;
          return {
            kind: 'dynPlace',
            type: f.type,
            path: {
              baseSlot: sv.slot,
              steps: [{ kind: 'field', fieldSlot: f.slot, fieldOffset: f.offset, fieldType: f.type }],
            },
          };
        }
        // this.o.inner = <struct>: a whole nested-struct field. Land writeStruct/copyStruct
        // at the field's slot (a storage place).
        if (f.type.kind === 'struct') {
          this.currentWritesState = true;
          return {
            kind: 'place',
            type: f.type,
            path: {
              baseSlot: sv.slot,
              steps: [{ kind: 'field', fieldSlot: f.slot, fieldOffset: f.offset, fieldType: f.type }],
            },
          };
        }
        // this.e.arr = <fixed array>: a whole FIXED-array field copy (a storage place; copyFixedArray
        // handles value/static elements). A dynamic-array or fixed-array-of-dynamic field stays gated.
        if (f.type.kind === 'array' && f.type.length !== undefined && isStaticType(f.type)) {
          this.currentWritesState = true;
          return {
            kind: 'place',
            type: f.type,
            path: {
              baseSlot: sv.slot,
              steps: [{ kind: 'field', fieldSlot: f.slot, fieldOffset: f.offset, fieldType: f.type }],
            },
          };
        }
        // this.s.arr = <array> (whole DYNAMIC value-element array field copy): a storage place at the
        // field's length slot (sv.slot + f.slot). copyArrayValueIntoStorage deep-copies the array value
        // (memory / calldata / array-literal / storage source) in, overwrite-clearing the old data.
        if (f.type.kind === 'array' && f.type.length === undefined && isStaticValueType(f.type.element)) {
          this.currentWritesState = true;
          return {
            kind: 'place',
            type: f.type,
            path: {
              baseSlot: sv.slot,
              steps: [{ kind: 'field', fieldSlot: f.slot, fieldOffset: f.offset, fieldType: f.type }],
            },
          };
        }
        if (!isStaticValueType(f.type)) {
          this.diags.error(node, 'JETH226', 'nested array field assignment is not supported yet');
          return undefined;
        }
        this.currentWritesState = true;
        return {
          kind: 'state',
          type: f.type,
          slot: sv.slot + BigInt(f.slot),
          offset: f.offset,
          varName: `${sv.name}.${f.name}`,
        };
      }
    }

    // this.stateVar
    if (ts.isPropertyAccessExpression(node) && node.expression.kind === ts.SyntaxKind.ThisKeyword) {
      if (this.constantsByName.has(node.name.text)) {
        this.diags.error(node, 'JETH054', `cannot assign to '@constant ${node.name.text}'`);
        return undefined;
      }
      // this.<immutable> = v: legal ONLY directly in the constructor body (matches solc, which also
      // rejects an assignment in a function called from the ctor). It writes the staged shadow.
      if (this.immutablesByName.has(node.name.text)) {
        const im = this.immutablesByName.get(node.name.text)!;
        if (!this.currentInConstructor) {
          this.diags.error(
            node,
            'JETH313',
            `@immutable '${node.name.text}' can only be assigned directly in the constructor body`,
          );
          return undefined;
        }
        return { kind: 'immutableStaged', type: im.type, name: im.name };
      }
      const v = this.stateByName.get(node.name.text);
      if (!v) {
        this.diags.error(node, 'JETH065', `unknown state variable 'this.${node.name.text}'`);
        return undefined;
      }
      if (v.type.kind === 'mapping') {
        this.diags.error(
          node,
          'JETH153',
          `cannot assign to mapping 'this.${node.name.text}' directly; assign an element (this.${node.name.text}[key] = ...)`,
        );
        return undefined;
      }
      this.currentWritesState = true;
      if (isBytesLike(v.type)) return { kind: 'dynState', type: v.type, slot: v.slot, varName: v.name };
      return { kind: 'state', type: v.type, slot: v.slot, offset: v.offset, varName: v.name };
    }
    // array element: a[i] = v  (a a state/fixed array `this.arr`, or a mapping-valued
    // dynamic array `this.m[k]` whose element is a value / bytes / string).
    if (ts.isElementAccessExpression(node) && this.assignableArrayElem(node)) {
      const arr = this.resolveArrayExpr(node.expression);
      if (!arr || !node.argumentExpression) return undefined;
      if (arr.base.kind === 'calldataArray') {
        this.diags.error(node, 'JETH214', 'a calldata array is read-only (cannot assign its elements)');
        return undefined;
      }
      // string[] / bytes[] element write: the element is a storage bytes/string
      // header at keccak(lenSlot)+i (strArrayElem); the RHS is a dynamic value.
      if (isBytesLike(arr.elem)) {
        // placeArray covers a struct-field / nested dynamic-element array (this.d.xs[i], this.dd[i][j]);
        // the element slot resolves at keccak(lenSlot)+i exactly like the state/fixed/mapping bases.
        if (
          arr.base.kind !== 'stateArray' &&
          arr.base.kind !== 'mapArray' &&
          arr.base.kind !== 'fixedArray' &&
          arr.base.kind !== 'placeArray'
        ) {
          this.diags.error(node, 'JETH217', 'this string[]/bytes[] element write is not supported yet');
          return undefined;
        }
        const index = this.checkExpr(node.argumentExpression, U256);
        if (!index) return undefined;
        this.currentWritesState = true;
        return { kind: 'strArrayElem', type: arr.elem, arr, index: this.coerce(index, U256, node.argumentExpression) };
      }
      // this.dd[i] = <array>: a whole inner-array element write. A DYNAMIC inner array
      // (`u256[]`) deep-copies into the element's length slot (codegen copyArrayValueIntoStorage);
      // a FIXED inner array (`Arr<u256,2>`) copies the static aggregate into the element base slot
      // (codegen copyFixedArray / writeArrayLit) - same source set as the whole-array `this.g = src`.
      // A whole-struct array-element write (this.recs[i] = D(...) / = this.x) is
      // supported: writeStruct/copyStruct lands at the element slot (Panic 0x32 on OOB).
      const index = this.checkExpr(node.argumentExpression, U256);
      if (!index) return undefined;
      const idx = this.coerce(index, U256, node.argumentExpression);
      if (!this.checkFixedBound(arr, idx, node.argumentExpression)) return undefined;
      if (arr.base.kind !== 'memArray' && arr.base.kind !== 'memArrayExpr') this.currentWritesState = true; // a memory array write is not storage
      return { kind: 'arrayElem', type: arr.elem, arr, index: idx };
    }

    // mapping element: this.m[k] (possibly nested)
    if (ts.isElementAccessExpression(node)) {
      const r = this.resolveMapAccess(node);
      if (!r) return undefined;
      if (r.valueType.kind === 'mapping') {
        this.diags.error(node, 'JETH153', 'cannot assign to a mapping value; index it fully');
        return undefined;
      }
      // this.m[k] = <bytes/string>: overwrite the dynamic value at the mapping slot
      // (storeDynamic clears the old tail, exactly like the bare `this.s = v` case).
      if (isBytesLike(r.valueType)) {
        this.currentWritesState = true;
        return { kind: 'mapDynState', type: r.valueType, baseSlot: r.baseSlot, keys: r.keys, keyTypes: r.keyTypes };
      }
      this.currentWritesState = true;
      return {
        kind: 'mapping',
        type: r.valueType,
        baseSlot: r.baseSlot,
        keys: r.keys,
        keyTypes: r.keyTypes,
        varName: r.varName,
      };
    }
    // local
    if (ts.isIdentifier(node)) {
      const t = this.lookupLocal(node.text);
      if (!t) {
        this.diags.error(node, 'JETH066', `assignment to unknown variable '${node.text}'`);
        return undefined;
      }
      return { kind: 'local', type: t, varName: node.text };
    }
    this.diags.error(node, 'JETH067', 'invalid assignment target');
    return undefined;
  }

  /** True iff `node` (an element access `X[i]`) is an array-element assignment: its
   *  base `X` resolves to a storage/fixed/mapping-valued array (`this.arr`, a local,
   *  or `this.m[k]` whose value is a dynamic array). Distinguishes `this.m[k][i] = v`
   *  on a mapping<K,T[]> (array-element write) from a nested-mapping key write. */
  private assignableArrayElem(node: ts.ElementAccessExpression): boolean {
    const bt = this.baseDynType(node.expression);
    if (bt && bt.kind === 'array') return true;
    const arr = this.resolveArrayExpr(node.expression);
    return (
      !!arr &&
      (arr.base.kind === 'mapArray' ||
        arr.base.kind === 'stateArray' ||
        arr.base.kind === 'fixedArray' ||
        arr.base.kind === 'placeArray' || // this.dd[i][j] = v, this.m[k][i][j] = v
        arr.base.kind === 'memArray' ||
        arr.base.kind === 'memArrayExpr') // (c ? xs : ys)[i] = v
    );
  }

  private lvalueAsExpr(lv: LValue): Expr {
    if (lv.kind === 'state') {
      this.currentReadsState = true;
      return { kind: 'stateRead', type: lv.type, slot: lv.slot, offset: lv.offset, varName: lv.varName };
    }
    if (lv.kind === 'mapping') {
      this.currentReadsState = true;
      return { kind: 'mapGet', type: lv.type, baseSlot: lv.baseSlot, keys: lv.keys, keyTypes: lv.keyTypes };
    }
    if (lv.kind === 'arrayElem') {
      if (lv.arr.base.kind !== 'memArray' && lv.arr.base.kind !== 'memArrayExpr') this.currentReadsState = true; // a memory array read is not storage
      return { kind: 'arrayGet', type: lv.type, arr: lv.arr, index: lv.index };
    }
    if (lv.kind === 'place') {
      this.currentReadsState = true;
      return { kind: 'placeRead', type: lv.type, path: lv.path };
    }
    // bytes/string lvalues (this.s, this.ss[i]): only plain `=` is valid; a compound
    // `op=` desugars through here, but buildBinary then rejects the bytes/string op.
    if (lv.kind === 'dynState') {
      this.currentReadsState = true;
      return { kind: 'dynStateRead', type: lv.type, slot: lv.slot };
    }
    if (lv.kind === 'mapDynState') {
      this.currentReadsState = true;
      return { kind: 'mapDynValue', type: lv.type, baseSlot: lv.baseSlot, keys: lv.keys, keyTypes: lv.keyTypes };
    }
    if (lv.kind === 'strArrayElem') {
      this.currentReadsState = true;
      return { kind: 'strArrayElem', type: lv.type, arr: lv.arr, index: lv.index };
    }
    if (lv.kind === 'dynPlace') {
      this.currentReadsState = true;
      return { kind: 'dynPlaceRead', type: lv.type, path: lv.path };
    }
    if (lv.kind === 'memField') {
      // a memory struct field read (for compound-assign / ++ on p.x): NOT storage.
      return { kind: 'memField', type: lv.type, local: lv.local, wordOffset: lv.wordOffset };
    }
    if (lv.kind === 'memElem') {
      // a fixed-array memory element read (for compound-assign / ++ on a[i] or p.a[i]): NOT storage.
      return {
        kind: 'memElem',
        type: lv.type,
        local: lv.local,
        index: lv.index,
        length: lv.length,
        wordOffset: lv.wordOffset,
      };
    }
    if (lv.kind === 'memDynField') {
      // a bytes/string memory-struct field read (no compound-assign/++ applies; type-checked away).
      return { kind: 'memDynField', type: lv.type, local: lv.local, wordOffset: lv.wordOffset };
    }
    if (lv.kind === 'immutableStaged') {
      // compound-assign / ++ on an @immutable in the constructor reads the staged shadow (solc
      // accepts `a += 1`, reading the current staged value, e.g. 0 before any assignment).
      return { kind: 'immutableStagedRead', type: lv.type, name: lv.name };
    }
    if (lv.kind === 'byteIndexStore') {
      // a storage-bytes byte read (for symmetry; compound-assign/++ on a bytes1 byte is rejected
      // elsewhere - bytesN has no arithmetic). The base is the bytes location read back.
      return { kind: 'byteIndex', type: lv.type, base: this.lvalueAsExpr(lv.loc), index: lv.index };
    }
    return { kind: 'localRead', type: lv.type, name: lv.varName };
  }

  // ---- mapping access / globals / casts (Phase 3) --------------------------

  /** Validate an array type for Phase 4b (single-level, static element). Returns
   *  true if usable; emits a diagnostic and returns false otherwise. */
  /** True if `t` is, or transitively contains (mapping value, array element, or
   *  struct field), a dynamic array of dynamic byte-sequence elements (string[]
   *  / bytes[]). Used to reject such types in storage, where per-element data
   *  slots are not yet implemented. */
  /** True if a struct field type `t` is a supported dynamic field kind (Phase
   *  4e-6). Supported: bytes/string, or a nested struct whose every field is
   *  itself static or a supported dynamic field. A dynamic array field of any
   *  kind is NOT supported (deferred). Static types are handled separately. */
  private isSupportedDynStructField(t: JethType): boolean {
    if (isBytesLike(t)) return true;
    if (t.kind === 'struct')
      return t.fields.every((f) => isStaticType(f.type) || this.isSupportedDynStructField(f.type));
    // a dynamic-array field (u256[], string[], D[], T[][]) or a fixed array of a dynamic
    // element: in storage the array lives at the field slot (length there, data at
    // keccak(fieldSlot)); the ABI codec encodes/decodes it via the recursive encoder.
    if (t.kind === 'array')
      return (
        isStaticType(t.element) ||
        isBytesLike(t.element) ||
        t.element.kind === 'array' ||
        this.isSupportedDynStructField(t.element)
      );
    return false;
  }

  /** True if a struct return type is shaped so the general tuple encoder (4e-6)
   *  can encode it: every field is a fully-static type (value / nested static
   *  struct / fixed static array) OR a supported dynamic field (bytes/string, or
   *  a nested struct that is itself a supported struct return). A dynamic-array
   *  field is NOT supported. */
  private isSupportedStructReturn(t: JethType & { kind: 'struct' }): boolean {
    // A fully-static struct return is encoded from storage by the recursive encoder
    // (structStorageLeaves flattens nested static structs and fixed-array fields), so
    // any static field shape is supported.
    if (!isDynamicType(t)) return t.fields.every((f) => isStaticType(f.type));
    // A dynamic struct return uses the general tuple encoder, which handles any
    // mix of static (value / nested static struct / static fixed-array) fields and
    // supported dynamic fields (bytes/string, or a nested supported struct).
    return t.fields.every((f) => isStaticType(f.type) || this.isSupportedDynStructField(f.type));
  }

  private containsDynElemArray(t: JethType): boolean {
    switch (t.kind) {
      case 'array':
        if (t.length === undefined && isBytesLike(t.element)) return true;
        return this.containsDynElemArray(t.element);
      case 'mapping':
        return this.containsDynElemArray(t.value);
      case 'struct':
        return t.fields.some((f) => this.containsDynElemArray(f.type));
      default:
        return false;
    }
  }

  /** True iff `t` is exactly a storage-supported `string[]` / `bytes[]`: either the
   *  bare dynamic array of a dynamic byte-sequence element, or a `mapping<K, ...>`
   *  chain whose final value is such an array. The element header lives at
   *  `keccak(lenSlot)+i` (a normal storage bytes/string), so the storage codec is
   *  reused per element. A `string[]` nested deeper (inside a struct, inside another
   *  array, or as a `string[][]`) is genuinely a later step and stays gated. */
  private isStorageStrArray(t: JethType): boolean {
    if (t.kind === 'mapping') return this.isStorageStrArray(t.value);
    return t.kind === 'array' && t.length === undefined && isBytesLike(t.element);
  }

  /** True if `t` is, or transitively contains (array element, mapping value), a
   *  DYNAMIC struct (a struct with >=1 dynamic field). Used to reject such a type
   *  in storage / mapping positions: the calldata-param / return tuple codec
   *  (4e-6) has no storage representation for the dynamic members yet. */
  private containsDynamicStruct(t: JethType): boolean {
    switch (t.kind) {
      case 'struct':
        return isDynamicType(t) || t.fields.some((f) => this.containsDynamicStruct(f.type));
      case 'array':
        return this.containsDynamicStruct(t.element);
      case 'mapping':
        return this.containsDynamicStruct(t.value);
      default:
        return false;
    }
  }

  /** True iff `t` is, or transitively contains (struct field / array element), a MAPPING (G7).
   *  Such a type is STORAGE-ONLY in Solidity: it cannot be a memory local, a function param or
   *  return, constructed, or copied - only a state var, a mapping value, or navigated into. */
  private typeHasMapping(t: JethType): boolean {
    if (t.kind === 'mapping') return true;
    if (t.kind === 'struct') return t.fields.some((f) => this.typeHasMapping(f.type));
    if (t.kind === 'array') return this.typeHasMapping(t.element);
    return false;
  }

  /** True iff `t` is exactly a storage-supported DYNAMIC STRUCT: either a dynamic
   *  struct (a `@struct` with >=1 dynamic field) whose every dynamic field is a
   *  bytes/string or a (recursively storage-supported) nested struct, OR a
   *  `mapping<K, ...>` chain whose final value is such a struct. A dynamic struct
   *  in storage occupies contiguous slots; each static field uses normal packed
   *  storage, and each bytes/string field at `base + fieldSlot` is a normal storage
   *  bytes/string (short inline / long with keccak(headerSlot) data slots), so the
   *  storage bytes/string codec is reused per field. A `D[]` (dynamic array of
   *  dynamic struct) or fixed `Arr<D,N>` is rejected EARLIER by gateArrayType (the
   *  element is not static); a dynamic-ARRAY struct field is impossible (rejected at
   *  @struct declaration, JETH229). So a dynamic struct that reaches this check is
   *  always storage-representable. */
  private isStorageDynStruct(t: JethType): boolean {
    if (t.kind === 'mapping') return this.isStorageDynStruct(t.value);
    // a dynamic array D[] (or mapping<K,D[]>) or a fixed Arr<D,N> of a storage-supported
    // dynamic struct: each element is a contiguous storageSlotCount(D) block (at
    // keccak(lenSlot)+i*stride for a dynamic array, or baseSlot+i*stride for a fixed one).
    if (t.kind === 'array') return this.isStorageDynStruct(t.element);
    if (t.kind !== 'struct' || !isDynamicType(t)) return false;
    return t.fields.every((f) => isStaticType(f.type) || this.isSupportedDynStructField(f.type));
  }

  /** Type-only walk: true iff `node` is a property/index chain rooted at a
   *  `this.<state-var>` that reads a bytes/string field of a STORAGE dynamic struct
   *  (this.d.s, this.e.b, this.recs[i].s, this.o.inner.s, this.m[k].s). Used to claim
   *  `this.<chain>.b[j]` byte-indexing for such a base. No diagnostics emitted. */
  private isStorageDynStructBytesField(node: ts.Expression): boolean {
    const steps: ({ field: string } | { index: true } | { mapKey: true })[] = [];
    let cur: ts.Expression = node;
    let rootType: JethType | undefined;
    for (;;) {
      if (ts.isPropertyAccessExpression(cur)) {
        if (cur.expression.kind === ts.SyntaxKind.ThisKeyword) {
          rootType = this.stateByName.get(cur.name.text)?.type;
          break;
        }
        steps.push({ field: cur.name.text });
        cur = cur.expression;
      } else if (ts.isElementAccessExpression(cur) && cur.argumentExpression) {
        steps.push({ index: true });
        cur = cur.expression;
      } else {
        return false;
      }
    }
    if (!rootType) return false;
    steps.reverse();
    let t: JethType = rootType;
    for (const s of steps) {
      if ('field' in s) {
        if (t.kind !== 'struct') return false;
        const f = t.fields.find((ff) => ff.name === s.field);
        if (!f) return false;
        t = f.type;
      } else {
        // index step: array element or mapping value.
        if (t.kind === 'array') t = t.element;
        else if (t.kind === 'mapping') t = t.value;
        else return false;
      }
    }
    return isBytesLike(t);
  }

  /** True if `t` is, or transitively contains, a NESTED dynamic array T[][] (a
   *  dynamic array whose element is itself a dynamic array). Per-element pointer
   *  tables are only implemented for the calldata-param / return form (4e-5);
   *  reject such a type in storage / mapping positions to avoid a silent
   *  miscompile. */
  private containsNestedDynArray(t: JethType): boolean {
    switch (t.kind) {
      case 'array':
        if (t.length === undefined && t.element.kind === 'array' && t.element.length === undefined) return true;
        return this.containsNestedDynArray(t.element);
      case 'mapping':
        return this.containsNestedDynArray(t.value);
      case 'struct':
        return t.fields.some((f) => this.containsNestedDynArray(f.type));
      default:
        return false;
    }
  }

  /** A dynamic array whose element chain (descending dynamic-array levels) reaches a
   *  static value type or bytes/string: u256[][], u256[][][], string[][], bytes[][],
   *  ... at ANY depth. Supported as a calldata param / return via the recursive codec. */
  private isAbiNestedDynArray(t: JethType): boolean {
    if (t.kind !== 'array' || t.length !== undefined) return false;
    const e = t.element;
    if (isStaticValueType(e) || isBytesLike(e)) return true;
    if (e.kind === 'struct' && (isStaticType(e) || this.isSupportedDynStructField(e))) return true; // Pt[][], D[][]
    if (e.kind === 'array' && e.length === undefined) return this.isAbiNestedDynArray(e);
    return false;
  }

  private gateArrayType(t: JethType, node: ts.Node, storage = false): boolean {
    if (t.kind !== 'array') return true;
    if (t.length === undefined) {
      // dynamic T[]: static value element (4b) or static struct element (4e-1).
      if (t.element.kind === 'array') {
        // Nested dynamic array of ANY depth (u256[][], u256[][][], string[][], ...):
        // supported as a calldata param / return via the recursive head/tail codec
        // (no nesting-level limit). The leaf (after descending dynamic-array levels)
        // must be a static value type or bytes/string. Storage / mapping positions are
        // rejected separately by the containsNestedDynArray guard.
        if (this.isAbiNestedDynArray(t)) return true;
        // a dynamic array whose element is a STATIC FIXED array (Arr<u256,2>[] = uint256[2][]):
        // in STORAGE (G6), element i occupies storageSlotCount(element) slots at keccak(p)+i*stride
        // (access/push/index/pop); as a calldata PARAM / RETURN it is a dynamic array of static
        // elements handled by the recursive head/tail codec.
        if (t.element.length !== undefined && isStaticType(t.element)) return true;
        // a dynamic array whose element is a FIXED array with DYNAMIC leaves (Arr<string,N>[],
        // Arr<bytes,N>[]): supported in STORAGE (element i at keccak(p)+i*stride, recursive place
        // codec handles access/push/index/pop with deep-clear) AND as a calldata PARAM / RETURN (the
        // recursive head/tail codec). Validate the element type recursively; a shape whose element is
        // not itself supported (e.g. Arr<Arr<string,2>,3>[]) falls through to JETH217. Verified
        // byte-identical to solc in both positions.
        if (t.element.length !== undefined) {
          const diagLen = this.diags.items.length;
          if (this.gateArrayType(t.element, node, storage)) return true;
          this.diags.items.length = diagLen; // discard the element's diagnostic; emit our own below
        }
        this.diags.error(node, 'JETH217', 'this nested dynamic array shape is not supported yet');
        return false;
      }
      if (t.element.kind === 'struct') {
        if (!isStaticType(t.element)) {
          // A dynamic array of a DYNAMIC struct (D[] where D has a bytes/string
          // field): in STORAGE each element occupies storageSlotCount(D) contiguous
          // slots; as a CALLDATA param / RETURN it is an array of dynamic elements
          // (offset table + per-element tuple), handled by the recursive codec.
          if (storage && this.isStorageDynStruct(t.element)) return true;
          if (!storage && this.isSupportedDynStructField(t.element)) return true;
          this.diags.error(node, 'JETH217', 'this dynamic-struct-array position is not supported yet');
          return false;
        }
        return true; // dynamic array of static struct
      }
      // dynamic array of dynamic byte-sequence element (string[] / bytes[], 4e-4):
      // head/tail of dynamic elements. Only supported as a calldata param / return.
      if (isBytesLike(t.element)) return true;
      if (!isStaticValueType(t.element)) {
        this.diags.error(node, 'JETH210', `array element type ${displayName(t.element)} is not supported yet`);
        return false;
      }
      return true;
    }
    // fixed Arr<T,N>: any static element (value, struct, or nested fixed array), OR a
    // DYNAMIC element (Arr<string,N>, Arr<bytes,N>, Arr<D,N>) as a calldata param /
    // return via the recursive codec (an N-word per-element offset table, no length).
    if (!isStaticType(t.element)) {
      // Arr<string,N> / Arr<bytes,N>: N contiguous string headers (storage) or an
      // N-word offset table (calldata/return).
      if (isBytesLike(t.element)) return true;
      // Arr<D,N> (fixed array of a DYNAMIC struct): N*slotCount(D) contiguous slots in
      // storage; an N-word offset table + per-element tuples as a calldata param/return.
      if (
        t.element.kind === 'struct' &&
        (storage ? this.isStorageDynStruct(t.element) : this.isSupportedDynStructField(t.element))
      )
        return true;
      // Arr<u256[],N> (= uint256[][N], a fixed array of DYNAMIC arrays). In STORAGE (G6):
      // element i is an inner dynamic array whose length slot is baseSlot+i*stride. As a
      // calldata PARAM / RETURN: an N-word offset table + per-element tails, handled by the
      // recursive head/tail codec (any supported nested dynamic-array element).
      if (t.element.kind === 'array') {
        if (
          storage ||
          this.isAbiNestedDynArray(t.element) ||
          (t.element.length === undefined && isStaticValueType(t.element.element))
        )
          return true;
        // a nested FIXED array element with dynamic leaves (Arr<Arr<string,2>,3> = string[2][3]): valid
        // as a calldata param / return if the inner element type is itself supported (recurse, with
        // diagnostic rollback so only our own JETH210 surfaces if the inner is unsupported).
        if (t.element.length !== undefined) {
          const diagLen = this.diags.items.length;
          if (this.gateArrayType(t.element, node, storage)) return true;
          this.diags.items.length = diagLen;
        }
      }
      this.diags.error(node, 'JETH210', `fixed-array element type ${displayName(t.element)} is not supported yet`);
      return false;
    }
    return true;
  }

  /** Resolve a `d.field...field` chain rooted at a DYNAMIC-struct calldata param
   *  (Phase 4e-6) into either a static-leaf read, a dynamic-field value, or a
   *  whole-struct value. Returns undefined when the root is not a dynamic-struct
   *  param (so other handlers run); commits (possibly with a diagnostic) once it
   *  owns the chain. Each step is a struct field; a field whose own value is
   *  dynamic resets the tuple-start base at codegen (spec section 3.2). The chain
   *  must end at a static value leaf, OR at a bytes/string dynamic field. */
  private resolveCdDynStruct(node: ts.Expression): { committed: true; result?: Expr } | undefined {
    const rawFields: ts.PropertyAccessExpression[] = [];
    let cur: ts.Expression = node;
    let rootName: string | undefined;
    let rootType: (JethType & { kind: 'struct' }) | undefined;
    for (;;) {
      if (ts.isPropertyAccessExpression(cur)) {
        if (cur.name.text === 'length') return undefined; // .length handled elsewhere
        rawFields.push(cur);
        cur = cur.expression;
      } else if (ts.isIdentifier(cur)) {
        const t = this.lookupLocal(cur.text);
        if (t && t.kind === 'struct' && isDynamicType(t)) {
          rootName = cur.text;
          rootType = t;
        }
        break;
      } else {
        return undefined; // an index step (or non-identifier root): not a bare dyn-struct field chain
      }
    }
    if (!rootName || !rootType || rawFields.length === 0) return undefined;
    rawFields.reverse(); // root -> leaf

    let t: JethType = rootType;
    const steps: CdDynStep[] = [];
    for (const fnode of rawFields) {
      if (t.kind !== 'struct') {
        this.diags.error(fnode, 'JETH210', `'${displayName(t)}' has no field '${fnode.name.text}'`);
        return { committed: true };
      }
      const idx = t.fields.findIndex((f) => f.name === fnode.name.text);
      if (idx < 0) {
        this.diags.error(fnode, 'JETH210', `struct '${t.name}' has no field '${fnode.name.text}'`);
        return { committed: true };
      }
      const f = t.fields[idx]!;
      // Tuple-head word offset: each preceding field contributes its inline static
      // words, or exactly ONE offset word if it is dynamic (spec section 3.0). Note
      // abiHeadWords would wrongly EXPAND a dynamic sub-struct into all its leaves.
      const headWords = t.fields
        .slice(0, idx)
        .reduce((n, ff) => n + (isDynamicType(ff.type) ? 1 : abiHeadWords(ff.type)), 0);
      steps.push({ headWords, fieldType: f.type, crossDynamic: isDynamicType(f.type) });
      t = f.type;
    }
    const place: CdDynPlace = { param: rootName, steps };
    if (isStaticValueType(t)) {
      return { committed: true, result: { kind: 'cdDynStructLeaf', type: t, place } };
    }
    if (isBytesLike(t)) {
      return { committed: true, result: { kind: 'cdDynStructField', type: t, place } };
    }
    // a dynamic value-element array field (s.xs where xs: u256[]): a calldata array reached via the
    // tuple tail offset. Indexing it (s.xs[i]) and echoing it whole (return s.xs) both decode the
    // array via calldataDynAt, then read/encode like any calldata array.
    if (t.kind === 'array' && t.length === undefined && isStaticValueType(t.element)) {
      return {
        committed: true,
        result: { kind: 'arrayValue', type: t, arr: { base: { kind: 'cdDynArrayField', place }, elem: t.element } },
      };
    }
    // an inline fixed-array-of-value field (s.xs where xs: Arr<T,N>): the N element words sit inline in
    // the tuple head at the field's byte offset (stride = 32, each static-value element is one ABI word).
    // Index it (s.xs[i], Panic 0x32 on i>=N) and read .length as the constant N. Mirrors the dynamic-field
    // index path but uses the inline head offset (no tail decode).
    if (t.kind === 'array' && t.length !== undefined && isStaticValueType(t.element)) {
      return {
        committed: true,
        result: {
          kind: 'arrayValue',
          type: t,
          arr: { base: { kind: 'cdDynFixedField', place, length: t.length }, elem: t.element },
        },
      };
    }
    // a dynamic array field whose ELEMENT is itself dynamic (string[]/bytes[], a nested
    // T[][], or a dynamic-struct D[]): the field's tail decodes to (tableStart, len) - one
    // offset word per element - exactly like cdDynArrayField with a 0x20 stride. Index it
    // (s.xs[i] -> element via the per-element offset table) and read .length at runtime.
    if (
      t.kind === 'array' &&
      t.length === undefined &&
      (isBytesLike(t.element) || t.element.kind === 'array' || t.element.kind === 'struct')
    ) {
      return {
        committed: true,
        result: { kind: 'arrayValue', type: t, arr: { base: { kind: 'cdDynArrayField', place }, elem: t.element } },
      };
    }
    // a whole nested STRUCT field (return o.inner): re-encode it as a standalone tuple from
    // the field's resolved calldata tuple-start (the generic dynamic-struct echo encoder).
    if (t.kind === 'struct') {
      return { committed: true, result: { kind: 'cdDynStructValue', type: t, param: rootName, place } };
    }
    // Ended at a shape with no codec yet.
    this.diags.error(
      node,
      'JETH230',
      `reading a whole ${displayName(t)} from a dynamic-struct calldata parameter is not supported yet (access a value field)`,
    );
    return { committed: true };
  }

  private resolveCdDynFieldPlace(node: ts.Expression): { place: CdDynPlace; type: JethType } | undefined {
    const rawFields: ts.PropertyAccessExpression[] = [];
    let cur: ts.Expression = node;
    let rootType: (JethType & { kind: 'struct' }) | undefined;
    let rootName: string | undefined;
    for (;;) {
      if (ts.isPropertyAccessExpression(cur)) {
        if (cur.name.text === 'length') return undefined;
        rawFields.push(cur);
        cur = cur.expression;
      } else if (ts.isIdentifier(cur)) {
        const t = this.lookupLocal(cur.text);
        if (t && t.kind === 'struct' && isDynamicType(t)) {
          rootName = cur.text;
          rootType = t;
        }
        break;
      } else {
        return undefined;
      }
    }
    if (!rootName || !rootType || rawFields.length === 0) return undefined;
    rawFields.reverse();
    let t: JethType = rootType;
    const steps: CdDynStep[] = [];
    for (const fnode of rawFields) {
      if (t.kind !== 'struct') return undefined;
      const idx = t.fields.findIndex((f) => f.name === fnode.name.text);
      if (idx < 0) return undefined;
      const f = t.fields[idx]!;
      const headWords = t.fields
        .slice(0, idx)
        .reduce((n, ff) => n + (isDynamicType(ff.type) ? 1 : abiHeadWords(ff.type)), 0);
      steps.push({ headWords, fieldType: f.type, crossDynamic: isDynamicType(f.type) });
      t = f.type;
    }
    return { place: { param: rootName, steps }, type: t };
  }

  /** Resolve a field/index chain rooted at an aggregate (struct or FIXED-array)
   *  function parameter into a CalldataPlace. Returns undefined when the root is
   *  not an aggregate param, letting the other handlers run. Once it owns the
   *  chain it commits (and may emit a diagnostic, returning no result). The ABI
   *  head is UNPACKED: each leaf is one 32-byte word, so steps carry head-word
   *  offsets, not storage slots. Dynamic-array params keep the cdArrays path. */
  /** Type-only walk of a field/index chain rooted at a struct/fixed-array param,
   *  returning the final type WITHOUT emitting diagnostics. Used so `.length` of a
   *  fixed-array field/element of a calldata aggregate resolves to its constant. */
  private calldataAccessType(node: ts.Expression): JethType | undefined {
    const steps: ({ field: string } | { index: true })[] = [];
    let cur: ts.Expression = node;
    let rootType: JethType | undefined;
    for (;;) {
      if (ts.isPropertyAccessExpression(cur)) {
        if (cur.name.text === 'length') return undefined;
        steps.push({ field: cur.name.text });
        cur = cur.expression;
      } else if (ts.isElementAccessExpression(cur) && cur.argumentExpression) {
        steps.push({ index: true });
        cur = cur.expression;
      } else if (ts.isIdentifier(cur)) {
        const t = this.lookupLocal(cur.text);
        // own only STATIC aggregate params (inline head): a static struct or a fixed
        // array of a static element. Arr<dyn,N> is a dynamic calldata array (cdArrays).
        if (t && (t.kind === 'struct' || (t.kind === 'array' && t.length !== undefined)) && isStaticType(t))
          rootType = t;
        break;
      } else {
        return undefined;
      }
    }
    if (!rootType) return undefined;
    steps.reverse();
    let t: JethType = rootType;
    for (const s of steps) {
      if ('field' in s) {
        if (t.kind !== 'struct') return undefined;
        const f = t.fields.find((ff) => ff.name === s.field);
        if (!f) return undefined;
        t = f.type;
      } else {
        if (!(t.kind === 'array' && t.length !== undefined)) return undefined;
        t = t.element;
      }
    }
    return t;
  }

  private resolveCalldataPlace(
    node: ts.Expression,
  ): { committed: true; result?: { place: CalldataPlace; finalType: JethType } } | undefined {
    const rawSteps: ({ field: ts.PropertyAccessExpression } | { index: ts.Expression })[] = [];
    let cur: ts.Expression = node;
    let rootName: string | undefined;
    let rootType: JethType | undefined;
    for (;;) {
      if (ts.isPropertyAccessExpression(cur)) {
        if (cur.name.text === 'length') return undefined; // .length handled elsewhere
        rawSteps.push({ field: cur });
        cur = cur.expression;
      } else if (ts.isElementAccessExpression(cur) && cur.argumentExpression) {
        rawSteps.push({ index: cur.argumentExpression });
        cur = cur.expression;
      } else if (ts.isIdentifier(cur)) {
        const t = this.lookupLocal(cur.text);
        // own only STATIC aggregate params: a fully-static struct, or a fixed array of
        // a STATIC element. A DYNAMIC struct is owned by resolveCdDynStruct; an
        // Arr<dyn,N> is a dynamic calldata array (cdArrays element paths).
        if (
          t &&
          ((t.kind === 'struct' && isStaticType(t)) ||
            (t.kind === 'array' && t.length !== undefined && isStaticType(t)))
        ) {
          rootName = cur.text;
          rootType = t;
        }
        break;
      } else {
        return undefined;
      }
    }
    if (!rootName || !rootType || rawSteps.length === 0) return undefined;
    rawSteps.reverse(); // root -> leaf

    let t: JethType = rootType;
    const steps: CdStep[] = [];
    for (const s of rawSteps) {
      if ('field' in s) {
        if (t.kind !== 'struct') {
          this.diags.error(s.field, 'JETH210', `'${displayName(t)}' has no field '${s.field.name.text}'`);
          return { committed: true };
        }
        const idx = t.fields.findIndex((f) => f.name === s.field.name.text);
        if (idx < 0) {
          this.diags.error(s.field, 'JETH210', `struct '${t.name}' has no field '${s.field.name.text}'`);
          return { committed: true };
        }
        const headWords = t.fields.slice(0, idx).reduce((n, f) => n + abiHeadWords(f.type), 0);
        steps.push({ kind: 'field', headWords, fieldType: t.fields[idx]!.type });
        t = t.fields[idx]!.type;
      } else {
        if (!(t.kind === 'array' && t.length !== undefined)) {
          this.diags.error(s.index, 'JETH212', `cannot index ${displayName(t)}`);
          return { committed: true };
        }
        const index = this.checkExpr(s.index, U256);
        if (!index) return { committed: true };
        const idx = this.coerce(index, U256, s.index);
        if (idx.kind === 'literalInt' && (idx.value < 0n || idx.value >= BigInt(t.length))) {
          this.diags.error(s.index, 'JETH211', `array index ${idx.value} out of bounds for length ${t.length}`);
          return { committed: true };
        }
        steps.push({
          kind: 'index',
          index: idx,
          strideWords: abiHeadWords(t.element),
          length: t.length,
          elemType: t.element,
        });
        t = t.element;
      }
    }
    if (!isStaticValueType(t)) {
      this.diags.error(
        node,
        'JETH230',
        'reading a whole struct/array from a calldata parameter is not supported yet (access a value field/element)',
      );
      return { committed: true };
    }
    return { committed: true, result: { place: { param: rootName, steps, finalType: t }, finalType: t } };
  }

  /** Resolve `<dynArrayOfStruct>[i].field` (a calldata param) into a cdArrayField
   *  read. Owns the shape once matched; returns the Expr, or undefined after a
   *  diagnostic. (Storage dynamic arrays of struct are gated elsewhere, so the
   *  array here is always a calldata param.) */
  /** Resolve `ds[i].field` where ds is a calldata D[] (dynamic-struct array): the
   *  element ds[i] is a dynamic tuple reached via the per-element offset table, then
   *  the field is read from that tuple (static leaf or bytes/string), reusing the
   *  dynamic-struct field access (CdDynPlace with an arrayRoot). */
  private resolveCdDynArrayField(
    node: ts.PropertyAccessExpression,
    struct: JethType & { kind: 'struct' },
  ): Expr | undefined {
    const elemAccess = node.expression as ts.ElementAccessExpression;
    const arr = this.resolveArrayExpr(elemAccess.expression);
    // the D[] is either a DIRECT calldata param (calldataArray) or a dynamic-struct-array
    // FIELD of a dyn-struct param (cdDynArrayField, e.g. s.items[i].name): both expose a
    // per-element offset table, so lowerCdDynBase's arrayRoot resolves the element tuple
    // identically (it reads the offset word at the table base + i*32).
    if (!arr || (arr.base.kind !== 'calldataArray' && arr.base.kind !== 'cdDynArrayField')) {
      this.diags.error(node, 'JETH217', 'this dynamic-struct-array element access is not supported');
      return undefined;
    }
    if (!elemAccess.argumentExpression) return undefined;
    const indexE = this.checkExpr(elemAccess.argumentExpression, U256);
    if (!indexE) return undefined;
    const index = this.coerce(indexE, U256, elemAccess.argumentExpression);
    const fidx = struct.fields.findIndex((f) => f.name === node.name.text);
    if (fidx < 0) {
      this.diags.error(node, 'JETH210', `struct '${struct.name}' has no field '${node.name.text}'`);
      return undefined;
    }
    const f = struct.fields[fidx]!;
    const headWords = struct.fields
      .slice(0, fidx)
      .reduce((n, ff) => n + (isDynamicType(ff.type) ? 1 : abiHeadWords(ff.type)), 0);
    const place: CdDynPlace = {
      param: '',
      steps: [{ headWords, fieldType: f.type, crossDynamic: isDynamicType(f.type) }],
      arrayRoot: { arr, index },
    };
    if (isStaticValueType(f.type)) return { kind: 'cdDynStructLeaf', type: f.type, place };
    if (isBytesLike(f.type)) return { kind: 'cdDynStructField', type: f.type, place };
    // a dynamic value-array field (ps[i].xs where xs: u256[]): a calldata array reached via the
    // tuple tail offset of the element tuple. Indexing it (ps[i].xs[j]) decodes the array via
    // calldataArrayAt, then reads the value element like any calldata array (mirrors s.xs).
    if (f.type.kind === 'array' && f.type.length === undefined && isStaticValueType(f.type.element)) {
      return {
        kind: 'arrayValue',
        type: f.type,
        arr: { base: { kind: 'cdDynArrayField', place }, elem: f.type.element },
      };
    }
    this.diags.error(
      node,
      'JETH230',
      'reading a whole nested struct/array field of a dynamic-struct array element is a later step',
    );
    return undefined;
  }

  private resolveCdArrayField(
    node: ts.PropertyAccessExpression,
    struct: JethType & { kind: 'struct' },
  ): Expr | undefined {
    // Peel the property-access chain `arr[i].f1.f2...fn` down to the element access
    // `arr[i]`, collecting the field names root->leaf. A one-deep `arr[i].f` has
    // node.expression === the ElementAccessExpression; a deeper `arr[i].inn.v` has
    // intermediate PropertyAccessExpression links. Each link traverses a STATIC
    // struct field, so the whole element (and every nested struct) is inline and the
    // leaf word sits at a single fixed displacement: the sum of abiHeadWords of all
    // fields preceding the chosen field at each level.
    const fieldNames: string[] = [];
    let cur: ts.Expression = node;
    while (ts.isPropertyAccessExpression(cur)) {
      fieldNames.push(cur.name.text);
      cur = cur.expression;
    }
    fieldNames.reverse(); // root -> leaf
    if (!ts.isElementAccessExpression(cur)) {
      this.diags.error(node, 'JETH217', 'this dynamic-array-of-struct access is a later step');
      return undefined;
    }
    const elemAccess = cur;
    const arr = this.resolveArrayExpr(elemAccess.expression);
    // a DIRECT calldata array param (calldataArray) OR a dynamic-struct param's array
    // FIELD (cdDynArrayField, e.g. p.pts[i].x): both lower to a calldata array ref with
    // a static-struct element stride, so cdArrayField indexes the leaf word identically.
    if (!arr || (arr.base.kind !== 'calldataArray' && arr.base.kind !== 'cdDynArrayField')) {
      this.diags.error(node, 'JETH217', 'this dynamic-array-of-struct access is a later step');
      return undefined;
    }
    // Walk the field chain through (possibly nested) static structs, accumulating the
    // leaf word displacement.
    let t: JethType = struct;
    let headWords = 0;
    for (const fname of fieldNames) {
      if (t.kind !== 'struct') {
        this.diags.error(node, 'JETH210', `'${displayName(t)}' has no field '${fname}'`);
        return undefined;
      }
      const fidx = t.fields.findIndex((f) => f.name === fname);
      if (fidx < 0) {
        this.diags.error(node, 'JETH210', `struct '${t.name}' has no field '${fname}'`);
        return undefined;
      }
      headWords += t.fields.slice(0, fidx).reduce((n, ff) => n + abiHeadWords(ff.type), 0);
      t = t.fields[fidx]!.type;
    }
    if (!isStaticValueType(t)) {
      this.diags.error(node, 'JETH230', 'reading a non-value field of a calldata struct-array element is a later step');
      return undefined;
    }
    if (!elemAccess.argumentExpression) return undefined;
    const index = this.checkExpr(elemAccess.argumentExpression, U256);
    if (!index) return undefined;
    const idx = this.coerce(index, U256, elemAccess.argumentExpression);
    return { kind: 'cdArrayField', type: t, arr, index: idx, headWords, fieldType: t };
  }

  /** Compile-time bounds check for a constant index into a fixed array (matches
   *  solc's "Out of bounds array access" compile error). */
  private checkFixedBound(arr: ArrayExpr, idx: Expr, node: ts.Node): boolean {
    if (arr.base.kind === 'fixedArray' && idx.kind === 'literalInt') {
      if (idx.value < 0n || idx.value >= BigInt(arr.base.length)) {
        this.diags.error(node, 'JETH211', `array index ${idx.value} out of bounds for length ${arr.base.length}`);
        return false;
      }
    }
    return true;
  }

  /** Compile-time bounds check for a constant index into a fixed-length MEMORY
   *  aggregate element (memElem); solc errors "Out of bounds array access" the
   *  same as for storage/calldata fixed arrays. */
  private checkMemElemBound(idx: Expr, length: number, node: ts.Node): boolean {
    if (idx.kind === 'literalInt' && (idx.value < 0n || idx.value >= BigInt(length))) {
      this.diags.error(node, 'JETH211', `array index ${idx.value} out of bounds for length ${length}`);
      return false;
    }
    return true;
  }

  /** Resolve `this.arr` or an array param into an ArrayExpr (single-level). */
  private resolveArrayExpr(node: ts.Expression): ArrayExpr | undefined {
    node = stripParens(node); // (xs)[i] / ((this.a))[i] index a parenthesized array base
    // (c ? xs : ys)[i]: a memory array produced by a ternary; the expr lowers to a pointer.
    if (ts.isConditionalExpression(node)) {
      const e = this.checkExpr(node);
      // a dynamic-array ternary already resolves to arrayValue{memArrayExpr{ternary}} - use it directly.
      if (e && e.kind === 'arrayValue' && e.arr.base.kind === 'memArrayExpr') return e.arr;
      if (e && e.type.kind === 'array' && e.type.length === undefined && isStaticValueType(e.type.element)) {
        return { base: { kind: 'memArrayExpr', expr: e }, elem: e.type.element };
      }
      return undefined;
    }
    if (ts.isPropertyAccessExpression(node) && node.expression.kind === ts.SyntaxKind.ThisKeyword) {
      const v = this.stateByName.get(node.name.text);
      if (v && v.type.kind === 'array') {
        if (v.type.length === undefined) return { base: { kind: 'stateArray', slot: v.slot }, elem: v.type.element };
        return { base: { kind: 'fixedArray', baseSlot: v.slot, length: v.type.length }, elem: v.type.element };
      }
      return undefined;
    }
    // p.xs: a dynamic value-array field of a dynamic-field struct memory local. The head word holds a
    // [len][elems] pointer; load it (memField) and wrap in memArrayExpr so index/.length consume it.
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isIdentifier(node.expression) &&
      this.memDynStructLocals.has(node.expression.text)
    ) {
      const mf = this.memDynStructField(node);
      if (mf && mf.field.type.kind === 'array' && mf.field.type.length === undefined) {
        const load: Expr = { kind: 'memField', type: U256, local: mf.local, wordOffset: mf.headWord };
        return { base: { kind: 'memArrayExpr', expr: load }, elem: mf.field.type.element };
      }
      return undefined;
    }
    if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression)) {
      const fp = this.resolveCdDynFieldPlace(node);
      // a struct-array field of a dyn-struct param (s.items where items: It[] or Pt[]): the
      // field's tail decodes to (tableStart, len) - the per-element offset table; whether the
      // element struct is static or dynamic, element ds[i] is resolved via that table (a static
      // struct element is contiguous, a dynamic one is offset-located inside the same table).
      if (fp && fp.type.kind === 'array' && fp.type.length === undefined && fp.type.element.kind === 'struct') {
        return { base: { kind: 'cdDynArrayField', place: fp.place }, elem: fp.type.element };
      }
    }
    if (ts.isIdentifier(node)) {
      const t = this.lookupLocal(node.text);
      // a MEMORY array local (let xs: u256[] = [...]): the register holds a pointer to
      // [len][elems]; element/length access reads memory.
      if (t && t.kind === 'array' && this.memArrayLocals.has(node.text)) {
        return { base: { kind: 'memArray', varName: node.text }, elem: t.element };
      }
      // a dynamic array param, OR a fixed array of a DYNAMIC element (Arr<dyn,N>),
      // both bound at codegen as a calldata array (the latter with a constant length).
      if (t && t.kind === 'array' && (t.length === undefined || isDynamicType(t.element))) {
        return { base: { kind: 'calldataArray', name: node.text }, elem: t.element };
      }
    }
    // `a[i]` where `a` is a MIXED calldata composite array param whose element is itself an
    // array, but NOT the all-dynamic nested case (owned by cdNestedElem below): dynamic-of-
    // fixed (Arr<u256,2>[]) or fixed-of-dynamic (Arr<u256[],N>). Resolves to the inner array
    // (fixed or dynamic) so a following [j] reads its element.
    if (ts.isElementAccessExpression(node) && ts.isIdentifier(node.expression) && node.argumentExpression) {
      const t = this.lookupLocal(node.expression.text);
      if (
        t &&
        t.kind === 'array' &&
        t.element.kind === 'array' &&
        (t.length === undefined || isDynamicType(t.element)) && // bound as a calldata array
        !(t.length === undefined && t.element.length === undefined) && // not all-dynamic (cdNestedElem)
        !this.memArrayLocals.has(node.expression.text)
      ) {
        const idx = this.checkExpr(node.argumentExpression, U256);
        if (!idx) return undefined;
        return {
          base: {
            kind: 'cdSubElem',
            name: node.expression.text,
            index: this.coerce(idx, U256, node.argumentExpression),
          },
          elem: t.element.element,
        };
      }
    }
    // An inner array reached by a chain of index steps into a nested dynamic array
    // calldata param (T[][], T[][][], string[][], ...). Walk inward collecting the
    // indices until the bare param identifier; descend the type tree by that many
    // dynamic-array levels. The resolved array (the value at m[i]/m[i][j]/...) must
    // itself be a dynamic array (length === undefined) for it to be an ArrayExpr; its
    // own element type is `elem`. Each [k] descends one level via the level's inner-
    // offset table at codegen (4e-5 / 4e-8). The root param's outermost level must be
    // a nested dynamic array (element is itself a dynamic array) so we never shadow the
    // ordinary single-level calldataArray / cdDynArrayElem paths.
    if (ts.isElementAccessExpression(node) && node.argumentExpression) {
      const indexNodes: ts.Expression[] = [];
      let cur: ts.Expression = node;
      while (ts.isElementAccessExpression(cur) && cur.argumentExpression) {
        indexNodes.push(cur.argumentExpression);
        cur = cur.expression;
      }
      if (ts.isIdentifier(cur)) {
        const root = this.lookupLocal(cur.text);
        if (
          root &&
          root.kind === 'array' &&
          root.length === undefined &&
          root.element.kind === 'array' &&
          !this.memArrayLocals.has(cur.text)
        ) {
          indexNodes.reverse(); // outer-to-inner
          // descend the type tree one ARRAY level per index step (a dynamic array OR a fixed-array-of-
          // dynamic, e.g. string[2][3] inside string[2][3][]). The codegen navigates each level via its
          // inner offset table (reading a length word only for a dynamic-array level).
          let t: JethType = root;
          for (let s = 0; s < indexNodes.length; s++) {
            if (t.kind !== 'array') return undefined; // not an array at this level
            t = t.element;
          }
          // the resolved value must itself be an array to be an ArrayExpr.
          if (t.kind !== 'array') return undefined;
          const indices: Expr[] = [];
          for (const inode of indexNodes) {
            const index = this.checkExpr(inode, U256);
            if (!index) return undefined;
            indices.push(this.coerce(index, U256, inode));
          }
          return { base: { kind: 'cdNestedElem', name: cur.text, indices }, elem: t.element };
        }
      }
    }
    // An inner array reached by indexing a NESTED-dynamic-array FIELD of a calldata
    // dynamic-struct param (s.grid[i] of u256[][], s.deep[i][j] of u256[][][]). Walk
    // inward collecting the indices until the field access s.grid; resolve the field via
    // the dyn-struct navigator. The field's outermost element must itself be a dynamic
    // array (so the single-level cdDynArrayField path - s.xs[i] - is never shadowed), and
    // the value reached after the indices must itself be a dynamic array to be an ArrayExpr.
    if (ts.isElementAccessExpression(node) && node.argumentExpression) {
      const indexNodes: ts.Expression[] = [];
      let cur: ts.Expression = node;
      while (ts.isElementAccessExpression(cur) && cur.argumentExpression) {
        indexNodes.push(cur.argumentExpression);
        cur = cur.expression;
      }
      if (ts.isPropertyAccessExpression(cur) && ts.isIdentifier(cur.expression)) {
        const fp = this.resolveCdDynFieldPlace(cur);
        if (
          fp &&
          fp.type.kind === 'array' &&
          fp.type.length === undefined &&
          fp.type.element.kind === 'array' // a nested-dynamic-array field: T[][], T[][][], string[][], ...
        ) {
          indexNodes.reverse(); // outer-to-inner
          let t: JethType = fp.type;
          for (let s = 0; s < indexNodes.length; s++) {
            if (t.kind !== 'array') return undefined;
            t = t.element;
          }
          if (t.kind !== 'array') return undefined; // the resolved value must itself be an array
          const indices: Expr[] = [];
          for (const inode of indexNodes) {
            const index = this.checkExpr(inode, U256);
            if (!index) return undefined;
            indices.push(this.coerce(index, U256, inode));
          }
          return { base: { kind: 'cdDynFieldNested', place: fp.place, indices }, elem: t.element };
        }
      }
    }
    // a mapping value that is a dynamic array: this.m[k] (possibly nested) -> T[].
    // Only attempt when the chain is rooted at a mapping state var (so we never
    // emit spurious diagnostics from resolveMapAccess on a non-mapping base).
    if (ts.isElementAccessExpression(node)) {
      let cur: ts.Expression = node;
      let numIndices = 0;
      while (ts.isElementAccessExpression(cur)) {
        numIndices++;
        cur = cur.expression;
      }
      if (ts.isPropertyAccessExpression(cur) && cur.expression.kind === ts.SyntaxKind.ThisKeyword) {
        const sv = this.stateByName.get(cur.name.text);
        if (sv && sv.type.kind === 'mapping') {
          // ONLY a pure mapping chain whose every index is a key and whose value is a
          // dynamic array (this.m[k]). If indices index INTO the array value
          // (this.m[k][i] on a mapping<K, T[][]>), decline so resolveStorageArrayPlace
          // (placeArray) owns it - resolveMapAccess would otherwise emit JETH152.
          let t: JethType = sv.type;
          let mapKeys = 0;
          while (t.kind === 'mapping' && mapKeys < numIndices) {
            t = t.value;
            mapKeys++;
          }
          if (mapKeys === numIndices && t.kind === 'array' && t.length === undefined) {
            const r = this.resolveMapAccess(node);
            if (r && r.valueType.kind === 'array' && r.valueType.length === undefined) {
              return {
                base: { kind: 'mapArray', baseSlot: r.baseSlot, keys: r.keys, keyTypes: r.keyTypes },
                elem: r.valueType.element,
              };
            }
          }
        }
      }
    }
    // A storage INNER dynamic array reached by a nested chain (this.dd[i] of u256[][],
    // this.s.xs dyn-array struct field, this.m[k].xs): build the AccessPath to the inner
    // array's length slot and wrap it in a placeArray (length / push / pop / index /
    // whole encode all reuse the storage-array machinery at that runtime slot).
    const place = this.resolveStorageArrayPlace(node);
    if (place) return { base: { kind: 'placeArray', path: place.path }, elem: place.elem };
    return undefined;
  }

  /** Build the AccessPath to a storage INNER dynamic array landing slot for a this-rooted
   *  chain (this.dd[i], this.dd[i][j], this.s.xs, this.m[k].xs): walks field / index /
   *  mapKey steps and returns the path + element type iff it lands on a dynamic array.
   *  Returns undefined (no diagnostic) for anything else. */
  private resolveStorageArrayPlace(node: ts.Expression): { path: AccessPath; elem: JethType } | undefined {
    const raw: ({ field: string } | { index: ts.Expression })[] = [];
    let cur: ts.Expression = node;
    let rootType: JethType | undefined;
    let baseSlot = -1n;
    for (;;) {
      if (ts.isPropertyAccessExpression(cur)) {
        if (cur.expression.kind === ts.SyntaxKind.ThisKeyword) {
          const v = this.stateByName.get(cur.name.text);
          if (!v) return undefined;
          baseSlot = v.slot;
          rootType = v.type;
          break;
        }
        if (cur.name.text === 'length') return undefined;
        raw.push({ field: cur.name.text });
        cur = cur.expression;
      } else if (ts.isElementAccessExpression(cur) && cur.argumentExpression) {
        raw.push({ index: cur.argumentExpression });
        cur = cur.expression;
      } else return undefined;
    }
    if (!rootType || raw.length === 0) return undefined; // a bare this.arr is the stateArray case
    raw.reverse();
    let t: JethType = rootType;
    const steps: AccessStep[] = [];
    for (const s of raw) {
      if ('field' in s) {
        if (t.kind !== 'struct') return undefined;
        const f = t.fields.find((ff) => ff.name === s.field);
        if (!f) return undefined;
        steps.push({ kind: 'field', fieldSlot: f.slot, fieldOffset: f.offset, fieldType: f.type });
        t = f.type;
      } else if (t.kind === 'array') {
        // a bytes/string element index is a byte-index, not a place: not our concern.
        if (t.length === undefined && isBytesLike(t.element)) return undefined;
        const idxE = this.checkExpr(s.index, U256);
        if (!idxE) return undefined;
        const idx = this.coerce(idxE, U256, s.index);
        if (t.length !== undefined)
          steps.push({
            kind: 'index',
            index: idx,
            strideSlots: storageSlotCount(t.element),
            length: t.length,
            elemType: t.element,
          });
        else
          steps.push({ kind: 'dynIndex', index: idx, strideSlots: storageSlotCount(t.element), elemType: t.element });
        t = t.element;
      } else if (t.kind === 'mapping') {
        const keyE = this.checkExpr(s.index, t.key);
        if (!keyE) return undefined;
        steps.push({ kind: 'mapKey', key: this.coerce(keyE, t.key, s.index), valueType: t.value });
        t = t.value;
      } else return undefined;
    }
    if (t.kind === 'array' && t.length === undefined) {
      this.currentReadsState = true;
      return { path: { baseSlot, steps }, elem: t.element };
    }
    return undefined;
  }

  /** True iff `node` is an index chain `m[i]...[k]` rooted at a calldata param whose
   *  type is a NESTED dynamic array (the outer element is itself a dynamic array, e.g.
   *  T[][], T[][][], string[][]). Used to recognise a nested-dynamic-array navigation
   *  before delegating to resolveArrayExpr / cdNestedElem. No diagnostics. */
  private nestedDynArrayRoot(node: ts.Expression): boolean {
    let cur: ts.Expression = node;
    while (ts.isElementAccessExpression(cur) && cur.argumentExpression) cur = cur.expression;
    if (!ts.isIdentifier(cur)) return false;
    const t = this.lookupLocal(cur.text);
    return (
      t !== undefined &&
      t.kind === 'array' &&
      t.length === undefined &&
      t.element.kind === 'array' && // a nested-array root: T[][], string[][], string[2][3][], ...
      !this.memArrayLocals.has(cur.text)
    );
  }

  /** Type of a directly-resolvable index base (`this.s` or a local/param), used to
   *  distinguish bytes-indexing `b[i]` from mapping access `this.m[k]`. Returns
   *  undefined for nested/complex bases (which go through the mapping resolver). */
  private baseDynType(expr: ts.Expression): JethType | undefined {
    expr = stripParens(expr);
    if (ts.isPropertyAccessExpression(expr) && expr.expression.kind === ts.SyntaxKind.ThisKeyword) {
      return this.stateByName.get(expr.name.text)?.type;
    }
    if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.expression)) {
      const fp = this.resolveCdDynFieldPlace(expr);
      if (fp && fp.type.kind === 'array' && fp.type.length === undefined && fp.type.element.kind === 'struct')
        return fp.type;
    }
    // msg.data is a calldata `bytes`, so `msg.data[i]` indexes it like any bytes value (Panic 0x32 OOB).
    if (
      ts.isPropertyAccessExpression(expr) &&
      ts.isIdentifier(expr.expression) &&
      expr.expression.text === 'msg' &&
      expr.name.text === 'data' &&
      !this.isVisibleLocal('msg') &&
      !this.stateByName.has('msg')
    ) {
      return { kind: 'bytes' };
    }
    // a bytes(<string|bytes>) / string(<bytes>) reinterpret cast is indexable as the cast's type, so
    // `bytes(s)[i]` byte-indexes the reinterpreted value (string(...) is then rejected as non-indexable
    // by the b[i] handler, matching solc). An invalid inner cast is rejected later by checkExpr.
    if (ts.isCallExpression(expr) && ts.isIdentifier(expr.expression) && expr.arguments.length === 1) {
      if (expr.expression.text === 'bytes') return { kind: 'bytes' };
      if (expr.expression.text === 'string') return { kind: 'string' };
    }
    if (ts.isIdentifier(expr)) return this.lookupLocal(expr.text);
    return undefined;
  }

  /** Resolve a NESTED storage chain (>=2 steps, involving a struct field or a
   *  fixed-array index) rooted at `this.<var>` into an AccessPath + final value
   *  type. Returns undefined for chains the flat handlers own (single step, or a
   *  pure-mapping chain), letting them run. Emits a diagnostic on a genuine error. */
  private resolveAccess(
    node: ts.Expression,
  ): { committed: true; result?: { path: AccessPath; finalType: JethType } } | undefined {
    const rawSteps: ({ field: ts.PropertyAccessExpression } | { index: ts.Expression })[] = [];
    let cur: ts.Expression = node;
    let baseSlot = -1n;
    let rootType: JethType | undefined;
    for (;;) {
      if (ts.isPropertyAccessExpression(cur)) {
        if (cur.expression.kind === ts.SyntaxKind.ThisKeyword) {
          const v = this.stateByName.get(cur.name.text);
          if (!v) return undefined;
          baseSlot = v.slot;
          rootType = v.type;
          break;
        }
        if (cur.name.text === 'length') return undefined; // handled by the .length branch
        rawSteps.push({ field: cur });
        cur = cur.expression;
      } else if (ts.isElementAccessExpression(cur) && cur.argumentExpression) {
        rawSteps.push({ index: cur.argumentExpression });
        cur = cur.expression;
      } else {
        return undefined;
      }
    }
    if (!rootType || rawSteps.length < 2) return undefined; // flat cases keep their handlers
    rawSteps.reverse(); // root -> leaf

    // Type-only pre-pass: decide ownership WITHOUT checking sub-expressions. Claim
    // the chain only if it involves a struct field or fixed-array index step;
    // pure-mapping chains stay with resolveMapAccess (which checks keys once).
    let pt: JethType = rootType;
    let hasAggregate = false;
    for (const s of rawSteps) {
      if ('field' in s) {
        if (pt.kind !== 'struct') break;
        const f = pt.fields.find((ff) => ff.name === s.field.name.text);
        if (!f) break;
        pt = f.type;
        hasAggregate = true;
      } else if (isBytesLike(pt)) {
        // An index step applied to a bytes/string value (e.g. this.e.b[j] where
        // this.e.b is a bytes field of a storage dynamic struct): a BYTE index, not a
        // storage place. Let the byteIndex handler own it rather than commit + reject.
        return undefined;
      } else if (pt.kind === 'array') {
        // Indexing a storage / mapping-valued string[]/bytes[] element is a dynamic
        // bytes/string value (header at keccak(lenSlot)+i); let the dedicated
        // strArrayElem handlers own it rather than the static-leaf place resolver.
        if (pt.length === undefined && isBytesLike(pt.element)) return undefined;
        pt = pt.element; // fixed or dynamic array index
        hasAggregate = true;
      } else if (pt.kind === 'mapping') {
        pt = pt.value;
      } else break;
    }
    if (!hasAggregate) return undefined; // not ours

    // Committed: fully resolve, type-check sub-expressions, emit diagnostics.
    let t: JethType = rootType;
    const steps: AccessStep[] = [];
    for (const s of rawSteps) {
      if ('field' in s) {
        if (t.kind !== 'struct') {
          this.diags.error(s.field, 'JETH210', `'${displayName(t)}' has no field '${s.field.name.text}'`);
          return { committed: true };
        }
        const f = t.fields.find((ff) => ff.name === s.field.name.text);
        if (!f) {
          this.diags.error(s.field, 'JETH210', `struct '${t.name}' has no field '${s.field.name.text}'`);
          return { committed: true };
        }
        steps.push({ kind: 'field', fieldSlot: f.slot, fieldOffset: f.offset, fieldType: f.type });
        t = f.type;
      } else {
        const idxNode = s.index;
        if (t.kind === 'array') {
          const elem = t.element;
          const packed = elem.kind !== 'struct' && elem.kind !== 'array' && storageByteSize(elem) < 32;
          const idxE = this.checkExpr(idxNode, U256);
          if (!idxE) return { committed: true };
          const idx = this.coerce(idxE, U256, idxNode);
          if (packed && t.length === undefined) {
            // a PACKED element of a DYNAMIC array in a nested access (this.m[k].ps[i], ps: u64[]):
            // data at keccak(lenSlot) with packing (perSlot per slot, runtime byte offset).
            const size = storageByteSize(elem);
            steps.push({ kind: 'packedDynIndex', index: idx, perSlot: Math.floor(32 / size), size, elemType: elem });
            t = elem;
            continue;
          }
          if (t.length !== undefined) {
            if (idx.kind === 'literalInt' && (idx.value < 0n || idx.value >= BigInt(t.length))) {
              this.diags.error(idxNode, 'JETH211', `array index ${idx.value} out of bounds for length ${t.length}`);
              return { committed: true };
            }
            if (packed) {
              // packed fixed-array element (perSlot per slot): runtime byte offset within the slot.
              const size = storageByteSize(elem);
              steps.push({
                kind: 'packedIndex',
                index: idx,
                perSlot: Math.floor(32 / size),
                size,
                length: t.length,
                elemType: elem,
              });
            } else {
              steps.push({
                kind: 'index',
                index: idx,
                strideSlots: storageSlotCount(elem),
                length: t.length,
                elemType: elem,
              });
            }
          } else {
            // dynamic T[]: runtime bound (sload) + data at keccak(lenSlot)
            steps.push({ kind: 'dynIndex', index: idx, strideSlots: storageSlotCount(elem), elemType: elem });
          }
          t = elem;
        } else if (t.kind === 'mapping') {
          const keyE = this.checkExpr(idxNode, t.key);
          if (!keyE) return { committed: true };
          steps.push({ kind: 'mapKey', key: this.coerce(keyE, t.key, idxNode), valueType: t.value });
          t = t.value;
        } else {
          this.diags.error(idxNode, 'JETH212', `cannot index ${displayName(t)}`);
          return { committed: true };
        }
      }
    }
    // The chain may end at a static value leaf (a packed-storage read/write) OR at
    // a bytes/string dynamic field of a storage dynamic struct (this.recs[i].s,
    // this.m[k].s, this.o.inner.s): the field header lives at the path's slot and
    // is a normal storage bytes/string. The caller branches on isBytesLike to emit
    // the dynamic-value node (dynPlaceRead / dynPlace) vs the static-leaf node.
    if (!isStaticValueType(t) && !isBytesLike(t)) {
      // A whole STRUCT leaf reached by an array-index last step (this.md[k][i],
      // this.recs[i] through a longer chain) is a struct array element: decline so the
      // dedicated structArrayElem handler (read via the storage encoder / write via
      // writeStruct/copyStruct at the element slot) owns it. Other whole-aggregate
      // leaves (a whole nested-struct field, a whole array) stay unsupported here.
      const lastStep = steps[steps.length - 1];
      if (t.kind === 'struct' && lastStep && (lastStep.kind === 'index' || lastStep.kind === 'dynIndex')) {
        return undefined;
      }
      // A whole STRUCT field reached by a field last step (this.recs[i].inner,
      // this.o.inner.deeper): produce the place; the read encodes it (placeRead -> the
      // storage encoder) and the write lands writeStruct/copyStruct at the field slot.
      if (t.kind === 'struct' && lastStep && lastStep.kind === 'field') {
        return { committed: true, result: { path: { baseSlot, steps }, finalType: t } };
      }
      // An inner DYNAMIC array leaf (this.s.xs, this.dd[i]) is owned by resolveArrayExpr
      // (placeArray) and the dedicated whole-inner-array read/write paths, not here.
      if (t.kind === 'array' && t.length === undefined && lastStep) return undefined;
      // A whole FIXED-array leaf reached at depth (this.g3[i][j]): produce the place; the
      // read encodes it from storage (placeRead -> returnStorageValue). The write is a
      // later step (gated in the assign handler).
      if (t.kind === 'array' && t.length !== undefined && lastStep) {
        return { committed: true, result: { path: { baseSlot, steps }, finalType: t } };
      }
      this.diags.error(
        node,
        'JETH226',
        `accessing a whole ${displayName(t)} is not supported yet (index/field it to a value)`,
      );
      return { committed: true };
    }
    return { committed: true, result: { path: { baseSlot, steps }, finalType: t } };
  }

  /** Resolve `this.m[k]...[k]` into base slot, coerced keys (outer->inner), key
   *  types, and the final value type. */
  private resolveMapAccess(
    node: ts.ElementAccessExpression,
  ): { baseSlot: bigint; keys: Expr[]; keyTypes: JethType[]; valueType: JethType; varName: string } | undefined {
    const indices: ts.Expression[] = [];
    let cur: ts.Expression = node;
    while (ts.isElementAccessExpression(cur)) {
      if (!cur.argumentExpression) {
        this.diags.error(cur, 'JETH150', 'mapping access requires an index expression');
        return undefined;
      }
      indices.push(cur.argumentExpression);
      cur = cur.expression;
    }
    indices.reverse(); // outer-to-inner

    if (!(ts.isPropertyAccessExpression(cur) && cur.expression.kind === ts.SyntaxKind.ThisKeyword)) {
      this.diags.error(cur, 'JETH151', 'mapping access must start at a state variable (this.m[...])');
      return undefined;
    }
    const v = this.stateByName.get(cur.name.text);
    if (!v) {
      this.diags.error(cur, 'JETH065', `unknown state variable 'this.${cur.name.text}'`);
      return undefined;
    }
    let t: JethType = v.type;
    const keys: Expr[] = [];
    const keyTypes: JethType[] = [];
    for (const idxNode of indices) {
      if (t.kind !== 'mapping') {
        this.diags.error(idxNode, 'JETH152', `cannot index ${displayName(t)} with [] (not a mapping)`);
        return undefined;
      }
      const keyExpr = this.checkExpr(idxNode, t.key);
      if (!keyExpr) return undefined;
      keys.push(this.coerce(keyExpr, t.key, idxNode));
      keyTypes.push(t.key);
      t = t.value;
    }
    return { baseSlot: v.slot, keys, keyTypes, valueType: t, varName: v.name };
  }

  private checkGlobal(node: ts.PropertyAccessExpression): Expr | undefined {
    const obj = (node.expression as ts.Identifier).text;
    const field = node.name.text;
    // msg.data: the complete calldata as `bytes` (selector included). Like msg.sig it is calldata,
    // so it is allowed even in @pure (no env/state read). Modeled as a calldata bytes view.
    if (obj === 'msg' && field === 'data') {
      return { kind: 'msgData', type: { kind: 'bytes' } };
    }
    const entry = GLOBALS[obj]?.[field];
    if (!entry) {
      this.diags.error(node, 'JETH160', `unknown global '${obj}.${field}'`);
      return undefined;
    }
    if (entry.cat === 'value') {
      // msg.value is an ENVIRONMENT read (forbidden in @pure, allowed in @view), like msg.sender.
      this.currentReadsEnv = true;
      // An EXTERNALLY-reachable function (external/public) reading msg.value must be @payable (solc
      // rejects a non-payable/view external read). An internal/private function may read it at any
      // non-pure mutability (the @pure check is handled by currentReadsEnv above). solc parity.
      if (this.currentExternallyReachable && this.currentMutability !== 'payable') {
        this.diags.error(node, 'JETH162', "'msg.value' in an externally-reachable function requires @payable");
      }
    } else if (entry.cat === 'env') {
      this.currentReadsEnv = true; // forbidden in @pure
    }
    // 'calldata' (msg.sig): allowed even in @pure; flag nothing.
    return { kind: 'global', type: entry.type, op: entry.op };
  }

  /** abi.encode / abi.encodePacked / abi.encodeWithSelector(bytes4 sel, ...) /
   *  abi.encodeWithSignature(string sig, ...) -> bytes. encodeWith* prepend a 4-byte selector to the
   *  standard encoding of the remaining args. No state/env read (pure). */
  private checkAbiEncode(node: ts.CallExpression, method: string): Expr | undefined {
    const packed = method === 'encodePacked';
    let rest = [...node.arguments];
    let selector: Expr | undefined;
    let sig: Expr | undefined;
    if (method === 'encodeWithSelector') {
      if (rest.length < 1) {
        this.diags.error(node, 'JETH173', 'abi.encodeWithSelector requires a bytes4 selector');
        return undefined;
      }
      // expect bytes4 so a 4-byte hex literal (0x12345678) converts implicitly, matching solc.
      const s = this.checkExpr(rest[0]!, { kind: 'bytesN', size: 4 });
      if (!s) return undefined;
      if (!(s.type.kind === 'bytesN' && s.type.size === 4)) {
        this.diags.error(
          rest[0]!,
          'JETH173',
          `abi.encodeWithSelector's first argument must be bytes4 (got ${displayName(s.type)})`,
        );
        return undefined;
      }
      selector = s;
      rest = rest.slice(1);
    } else if (method === 'encodeWithSignature') {
      if (rest.length < 1) {
        this.diags.error(node, 'JETH173', 'abi.encodeWithSignature requires a string signature');
        return undefined;
      }
      const s = this.checkExpr(rest[0]!, { kind: 'string' }); // a string-literal sig needs the string context
      if (!s) return undefined;
      if (s.type.kind !== 'string') {
        this.diags.error(
          rest[0]!,
          'JETH173',
          `abi.encodeWithSignature's first argument must be string (got ${displayName(s.type)})`,
        );
        return undefined;
      }
      sig = s;
      rest = rest.slice(1);
    }
    const args: Expr[] = [];
    for (const a of rest) {
      // a bare string literal arg (abi.encodePacked("DOMAIN")) needs the string context to type-check.
      const exp =
        ts.isStringLiteral(a) || ts.isNoSubstitutionTemplateLiteral(a) ? ({ kind: 'string' } as JethType) : undefined;
      const e = this.checkExpr(a, exp);
      if (!e) return undefined;
      // packed: value + bytes/string only. standard (incl. encodeWith*) also accepts a STATIC
      // struct/fixed-array (encoded inline) and a DYNAMIC value-element array (offset + tail).
      // Nested-dynamic (string[], T[][]) / dynamic struct args stay a later step.
      const t = e.type;
      const aggOk = packed
        ? // packed: a value-element array (fixed or dynamic); each element padded to 32 bytes, no length.
          // solc rejects a struct / nested-element array in packed mode (so JETH does too).
          t.kind === 'array' && isStaticValueType(t.element)
        : (isStaticType(t) && (t.kind === 'struct' || t.kind === 'array')) || // static struct/fixed-array (inline)
          (t.kind === 'struct' && this.isSupportedDynStructLocal(t)) || // dynamic struct (offset + tail)
          t.kind === 'array'; // dynamic array OR fixed array of dynamic elements (offset + tail)
      if (!isStaticValueType(t) && !isBytesLike(t) && !aggOk) {
        this.diags.error(
          a,
          'JETH173',
          `abi.${method} supports ${packed ? 'value-type and bytes/string' : 'value-type, bytes/string, static struct/fixed-array, and dynamic value-array'} arguments (got ${displayName(t)})`,
        );
        return undefined;
      }
      args.push(e);
    }
    return { kind: 'abiEncode', type: { kind: 'bytes' }, packed, args, selector, sig };
  }

  /** Which decoded types abi.decode supports (v1). The memory-sourced decode codec (abiDecFromMem,
   *  the analogue of the calldata->memory codec) composes over: any value type (uintN/intN/bool/
   *  address/bytesN/enum/branded), bytes/string, a dynamic value-element array T[], a static fixed
   *  array Arr<T,N> of static leaves, a fully-static struct, and a dynamic struct of value/bytes/
   *  string/dynamic-value-array fields. Nested-dynamic arrays (string[]/T[][]), arrays/structs whose
   *  elements are themselves dynamic structs, and nested-struct fields stay a CLEAN rejection. */
  private decodeSupported(t: JethType): boolean {
    if (isStaticValueType(t) || isBytesLike(t)) return true;
    if (t.kind === 'array') {
      if (t.length === undefined) {
        // a dynamic array of a VALUE element (head/tail). A bytes/string-element array (string[] /
        // bytes[]) is a CLEAN rejection: JETH has no memory-local representation for it (the codec
        // could decode it, but there is nowhere to bind the result), so reject rather than miscompile.
        return isStaticValueType(t.element);
      }
      // a static fixed array: supported when its leaves are static value types (inline aggregate).
      return isStaticType(t) && this.isStaticLeafArray(t);
    }
    // struct results stay a CLEAN rejection in v1: the decode codec produces the standard ABI
    // head/tail layout, but a JETH dynamic-struct memory local is POINTER-headed (a head word holds a
    // memory pointer to each dynamic field's [len][data] image, not an ABI offset). Reconciling the
    // two representations cannot be verified byte-identical cheaply, so a struct target is rejected.
    return false;
  }

  /** A fixed array whose every leaf (recursively unwrapping fixed-array nesting) is a static value
   *  type, so abiDecFromMem's static-aggregate branch copies it inline word-for-word. */
  private isStaticLeafArray(t: JethType): boolean {
    if (t.kind === 'array' && t.length !== undefined) return this.isStaticLeafArray(t.element);
    return isStaticValueType(t);
  }

  /** Resolve the common shape of abi.decode(data, T-or-[T...]) and `<bytes>.decode(T-or-[T...])`:
   *  the source bytes Expr plus the resolved decoded type list (one entry for the single form, N for
   *  the tuple form). Emits the diagnostic and returns undefined on any error (bad arity, a non-bytes
   *  source, an unresolvable / unsupported type). `dataNode` is the bytes source expression and
   *  `typeNode` the type argument (a bare type, `T[]`, `Arr<T,N>`, or `[T1, ...]`). */
  private resolveAbiDecode(
    site: ts.Node,
    dataNode: ts.Expression,
    typeNode: ts.Expression,
  ): { data: Expr; types: JethType[]; tuple: boolean } | undefined {
    const data = this.checkExpr(dataNode, BYTES);
    if (!data) return undefined;
    if (data.type.kind !== 'bytes') {
      this.diags.error(
        dataNode,
        'JETH320',
        `abi.decode(...) requires a bytes value to decode, got ${displayName(data.type)}`,
      );
      return undefined;
    }
    const tuple = ts.isArrayLiteralExpression(typeNode);
    const typeExprs = tuple ? [...(typeNode as ts.ArrayLiteralExpression).elements] : [typeNode];
    if (tuple && typeExprs.length < 1) {
      this.diags.error(typeNode, 'JETH321', 'abi.decode(...) tuple type list must have at least one type');
      return undefined;
    }
    const types: JethType[] = [];
    for (const te of typeExprs) {
      const t = this.resolveTypeExpr(te as ts.Expression);
      if (!t) {
        this.diags.error(
          te,
          'JETH321',
          'abi.decode(...) second argument must be a type name, `T[]`, `Arr<T, N>`, or a tuple `[T1, T2, ...]` of those',
        );
        return undefined;
      }
      if (!this.decodeSupported(t)) {
        this.diags.error(
          te,
          'JETH322',
          `abi.decode(...) does not support decoding to '${displayName(t)}' yet (supported: value types, bytes, string, T[], Arr<T, N>, and structs of those)`,
        );
        return undefined;
      }
      types.push(t);
    }
    return { data, types, tuple };
  }

  /** abi.decode(data, T) / abi.decode(data, [T1, ...]) in VALUE position. The single form yields one
   *  decoded value Expr (kind 'abiDecode'); the tuple form is only valid in a destructuring and errors
   *  here (mirrors tryCall's value-position rejection). */
  private checkAbiDecode(node: ts.CallExpression): Expr | undefined {
    if (node.arguments.length !== 2) {
      this.diags.error(
        node,
        'JETH320',
        'abi.decode(...) takes exactly two arguments: the bytes value and the target type',
      );
      return undefined;
    }
    const r = this.resolveAbiDecode(node, node.arguments[0]!, node.arguments[1]!);
    if (!r) return undefined;
    if (r.tuple) {
      this.diags.error(
        node,
        'JETH323',
        'a multi-type abi.decode(...) yields a tuple; bind it with a destructuring `let [a, b] = abi.decode(...)`',
      );
      return undefined;
    }
    return { kind: 'abiDecode', type: r.types[0]!, data: r.data };
  }

  /** Recognize the `<bytes>.decode(T)` / `<bytes>.decode([T1, ...])` method sugar. It is exact sugar
   *  for abi.decode(<bytes>, T): the receiver is any bytes value (a local, a calldata param, an
   *  abi.encode result, the returndata of addr.call({...}), ...). Returns the rewritten call shape
   *  (data node + type node) or undefined when this is not a `.decode(...)` of a bytes value. */
  private abiDecodeMethod(node: ts.CallExpression): { data: ts.Expression; typeArg: ts.Expression } | undefined {
    if (!ts.isPropertyAccessExpression(node.expression) || node.expression.name.text !== 'decode') return undefined;
    if (node.arguments.length !== 1) return undefined;
    return { data: node.expression.expression, typeArg: node.arguments[0]! };
  }

  /** Speculatively determine whether `node` is a bytes value (with diagnostic rollback so the peek
   *  emits nothing). Used to decide whether `<expr>.decode(T)` is the abi.decode method sugar before
   *  committing to that interpretation; a non-bytes receiver falls through to normal handling. */
  private isBytesValueExpr(node: ts.Expression): boolean {
    const diagLen = this.diags.items.length;
    const e = this.checkExpr(node);
    this.diags.items.length = diagLen;
    return !!e && e.type.kind === 'bytes';
  }

  /** A template literal `Hello ${name}` -> a string.concat of its cooked literal parts (as string
   *  literals) and its interpolated expressions, each of which must be `string`-typed (Solidity has no
   *  implicit conversion to string). Desugars to the packed-abiEncode machinery typed as a string,
   *  byte-identical to solc `string.concat("Hello ", name)`. */
  private checkTemplateLiteral(node: ts.TemplateExpression): Expr | undefined {
    const parts: Expr[] = [];
    const pushText = (text: string) => {
      if (text.length > 0) parts.push({ kind: 'stringLiteral', type: STRING, bytes: new TextEncoder().encode(text) });
    };
    pushText(node.head.text);
    let ok = true;
    for (const span of node.templateSpans) {
      const e = this.checkExpr(span.expression, STRING);
      if (!e) {
        ok = false;
        continue;
      }
      if (e.type.kind !== 'string') {
        this.diags.error(
          span.expression,
          'JETH384',
          `a template interpolation must be a string, got ${displayName(e.type)} (Solidity string.concat only concatenates strings)`,
        );
        ok = false;
        continue;
      }
      parts.push(e);
      pushText(span.literal.text);
    }
    if (!ok) return undefined;
    return this.makeConcat(parts, STRING);
  }

  /** Build a concatenation of bytes/string `parts` typed as `result` (STRING or BYTES), byte-identical to
   *  solc string.concat / bytes.concat (a tightly-packed concatenation == abi.encodePacked of the parts):
   *  0 parts -> the empty value; 1 part -> that part unchanged; otherwise a packed abiEncode node. */
  private makeConcat(parts: Expr[], result: JethType): Expr {
    if (parts.length === 0) return { kind: 'stringLiteral', type: result, bytes: new Uint8Array(0) };
    // a single part can be returned unchanged ONLY if it already has the result type; a bytesN part in a
    // bytes.concat (or any type mismatch) must be repacked through the encoder to become a `bytes` value.
    if (parts.length === 1 && parts[0]!.type.kind === result.kind) return parts[0]!;
    return { kind: 'abiEncode', type: result, packed: true, args: parts };
  }

  /** `<string|bytes>.concat(args...)` and the static `string.concat(...)` / `bytes.concat(...)` forms.
   *  string.concat takes string args -> string; bytes.concat takes bytes/bytesN args -> bytes. Both are a
   *  tightly-packed concatenation, byte-identical to solc (== abi.encodePacked, reinterpreted). Returns the
   *  Expr, 'reject' (diagnostic emitted), or undefined (not a concat - let other handlers try). */
  private resolveConcat(node: ts.CallExpression): Expr | 'reject' | undefined {
    if (!ts.isPropertyAccessExpression(node.expression) || node.expression.name.text !== 'concat') return undefined;
    const recvNode = node.expression.expression;
    // static `string.concat(...)` / `bytes.concat(...)`: the receiver is the bare type keyword.
    if (ts.isIdentifier(recvNode) && (recvNode.text === 'string' || recvNode.text === 'bytes')) {
      if (!this.isVisibleLocal(recvNode.text) && !this.stateByName.has(recvNode.text)) {
        const isStr = recvNode.text === 'string';
        const args = this.checkConcatArgs([...node.arguments], isStr);
        if (args === undefined) return 'reject';
        return this.makeConcat(args, isStr ? STRING : BYTES);
      }
    }
    // method form `<value>.concat(...)`: peek-rollback so a non-string/bytes receiver falls through. A
    // string-literal receiver ("x".concat(y)) needs an expected type to resolve as a string value.
    const recvExpected =
      ts.isStringLiteral(recvNode) || ts.isNoSubstitutionTemplateLiteral(recvNode) ? STRING : undefined;
    const savedEnv = this.currentReadsEnv;
    const savedReads = this.currentReadsState;
    const savedWrites = this.currentWritesState;
    const diagLen = this.diags.items.length;
    const peek = this.checkExpr(recvNode, recvExpected);
    const isStr = !!peek && peek.type.kind === 'string';
    const isByt = !!peek && peek.type.kind === 'bytes';
    this.diags.items.length = diagLen;
    this.currentReadsEnv = savedEnv;
    this.currentReadsState = savedReads;
    this.currentWritesState = savedWrites;
    if (!isStr && !isByt) return undefined;
    const recv = this.checkExpr(recvNode, recvExpected);
    if (!recv) return 'reject';
    const args = this.checkConcatArgs([...node.arguments], isStr);
    if (args === undefined) return 'reject';
    return this.makeConcat([recv, ...args], isStr ? STRING : BYTES);
  }

  /** Type-check concat arguments: string.concat wants `string`, bytes.concat wants `bytes`/`bytesN`.
   *  Returns the checked Exprs, or undefined if any arg is missing or the wrong type (diagnostic emitted). */
  private checkConcatArgs(argNodes: ts.Expression[], isStr: boolean): Expr[] | undefined {
    const out: Expr[] = [];
    let ok = true;
    for (const an of argNodes) {
      const a = this.checkExpr(an, isStr ? STRING : BYTES);
      if (!a) {
        ok = false;
        continue;
      }
      const good = isStr ? a.type.kind === 'string' : a.type.kind === 'bytes' || a.type.kind === 'bytesN';
      if (!good) {
        this.diags.error(
          an,
          'JETH385',
          isStr
            ? `string.concat(...) only accepts string arguments, got ${displayName(a.type)}`
            : `bytes.concat(...) only accepts bytes / bytesN arguments, got ${displayName(a.type)}`,
        );
        ok = false;
        continue;
      }
      out.push(a);
    }
    return ok ? out : undefined;
  }

  /** Is `e` a CALLDATA-located bytes/string value (sliceable)? A bytes/string parameter (dynParamRead),
   *  msg.data (msgData), another slice (calldataSlice), a bytes/string field of a calldata dynamic-struct
   *  param (cdDynStructField), or a bytes[]/string[] calldata element (cdDynArrayElem) - and a
   *  bytes(string)/string(bytes) cast over any of those. Each of these lowers to a calldata DynRef
   *  ({ src:'calldata', dataPtr, len }), which the slice adjusts in place. A memory/storage bytes is NOT
   *  calldata (solc only slices calldata), so strArrayElem/dynPlaceRead (storage) are deliberately absent. */
  private isCalldataBytes(e: Expr): boolean {
    if (e.kind === 'cast') return this.isCalldataBytes(e.operand);
    return (
      e.kind === 'dynParamRead' ||
      e.kind === 'msgData' ||
      e.kind === 'calldataSlice' ||
      e.kind === 'cdDynStructField' ||
      e.kind === 'cdDynArrayElem'
    );
  }

  /** `<calldata bytes>.slice(start [, end])` -> a zero-copy calldata bytes slice (solc data[start:end]).
   *  Returns the Expr, 'reject' (a diagnostic was emitted, stop), or undefined (not a bytes `.slice` -
   *  let other handlers try). Peek-rollback first so a non-bytes `.slice` receiver does not get claimed. */
  private resolveCalldataSlice(node: ts.CallExpression): Expr | 'reject' | undefined {
    if (!ts.isPropertyAccessExpression(node.expression) || node.expression.name.text !== 'slice') return undefined;
    const recvNode = node.expression.expression;
    // peek whether the receiver is a bytes value, restoring diagnostics AND the mutability flags so a
    // non-slice fall-through leaves no trace (the real handler re-checks the receiver and sets flags).
    const savedEnv = this.currentReadsEnv;
    const savedReads = this.currentReadsState;
    const savedWrites = this.currentWritesState;
    const diagLen = this.diags.items.length;
    const peek = this.checkExpr(recvNode);
    // bytes AND string calldata are sliceable (solc allows string calldata slices too).
    const isSliceable = !!peek && (peek.type.kind === 'bytes' || peek.type.kind === 'string');
    this.diags.items.length = diagLen;
    this.currentReadsEnv = savedEnv;
    this.currentReadsState = savedReads;
    this.currentWritesState = savedWrites;
    if (!isSliceable) return undefined;
    // commit: re-check the receiver (keeping diagnostics + flags this time)
    const base = this.checkExpr(recvNode);
    if (!base) return 'reject';
    if (!this.isCalldataBytes(base)) {
      this.diags.error(
        node,
        'JETH382',
        '.slice(...) is only valid on a calldata bytes/string value (a parameter, msg.data, a slice, or a calldata struct field / array element); a memory/storage value cannot be sliced',
      );
      return 'reject';
    }
    if (node.arguments.length > 2) {
      this.diags.error(node, 'JETH170', '.slice(...) takes an optional start and end argument');
      return 'reject';
    }
    // .slice() = the whole value (start 0), .slice(s) = [s:], .slice(s, e) = [s:e]. Indices must be uint.
    let start: Expr;
    if (node.arguments.length === 0) {
      start = { kind: 'literalInt', type: U256, value: 0n };
    } else {
      const s = this.checkExpr(node.arguments[0]!, U256);
      if (!s) return 'reject';
      if (s.type.kind !== 'uint') {
        this.diags.error(
          node.arguments[0]!,
          'JETH383',
          `.slice(...) start must be an unsigned integer, got ${displayName(s.type)}`,
        );
        return 'reject';
      }
      start = this.coerce(s, U256, node.arguments[0]!);
    }
    let end: Expr | undefined;
    if (node.arguments.length === 2) {
      const e = this.checkExpr(node.arguments[1]!, U256);
      if (!e) return 'reject';
      if (e.type.kind !== 'uint') {
        this.diags.error(
          node.arguments[1]!,
          'JETH383',
          `.slice(...) end must be an unsigned integer, got ${displayName(e.type)}`,
        );
        return 'reject';
      }
      end = this.coerce(e, U256, node.arguments[1]!);
    }
    // the slice preserves the base location type (bytes -> bytes, string -> string).
    return { kind: 'calldataSlice', type: base.type, base, start, end };
  }

  /** A G1Point/G2Point @struct shape check: exactly `n` u256 fields (n=2 for G1, n=4 for G2). A too-loose
   *  check would emit a wrong-size staticcall buffer, so the field count and width are pinned. */
  private isPointStruct(t: JethType, n: number): boolean {
    return (
      t.kind === 'struct' &&
      t.fields.length === n &&
      t.fields.every((f) => f.type.kind === 'uint' && f.type.bits === 256)
    );
  }

  private checkBn256Call(node: ts.CallExpression, callee: 'bn256Add' | 'bn256Mul' | 'bn256Pairing'): Expr | undefined {
    if (callee === 'bn256Pairing') {
      // packed-bytes form: bn256Pairing(input: bytes): bool. staticcall 0x08, empty input -> true,
      // a non-192-multiple length reverts EMPTY at runtime (byte-identical to solc).
      if (node.arguments.length !== 1) {
        this.diags.error(node, 'JETH170', 'bn256Pairing(...) takes exactly one argument (input: bytes)');
        return undefined;
      }
      const input = this.checkExpr(node.arguments[0]!, this.bytesLiteralExpected(node.arguments[0]!));
      if (!input) return undefined;
      if (input.type.kind !== 'bytes') {
        this.diags.error(
          node.arguments[0]!,
          'JETH171',
          `bn256Pairing(...) requires a bytes argument, got ${displayName(input.type)} (pack pairs with abi.encodePacked(...))`,
        );
        return undefined;
      }
      return { kind: 'bn256', type: BOOL, op: 'pairing', addr: 8, args: [input], insize: 'dynamic', outsize: 32 };
    }
    if (callee === 'bn256Add') {
      if (node.arguments.length !== 2) {
        this.diags.error(node, 'JETH170', 'bn256Add(...) takes exactly two G1Point arguments');
        return undefined;
      }
      const a = this.checkExpr(node.arguments[0]!);
      const b = this.checkExpr(node.arguments[1]!);
      if (!a || !b) return undefined;
      for (const [x, i] of [
        [a, 0],
        [b, 1],
      ] as const) {
        if (!this.isPointStruct(x.type, 2)) {
          this.diags.error(
            node.arguments[i]!,
            'JETH171',
            `bn256Add(...) requires a G1Point (a @struct of exactly 2 u256 fields), got ${displayName(x.type)}`,
          );
          return undefined;
        }
      }
      return { kind: 'bn256', type: a.type, op: 'add', addr: 6, args: [a, b], insize: 128, outsize: 64 };
    }
    // bn256Mul(p: G1Point, s: u256): G1Point
    if (node.arguments.length !== 2) {
      this.diags.error(node, 'JETH170', 'bn256Mul(...) takes a G1Point and a u256 scalar');
      return undefined;
    }
    const p = this.checkExpr(node.arguments[0]!);
    const s = this.checkExpr(node.arguments[1]!, U256);
    if (!p || !s) return undefined;
    if (!this.isPointStruct(p.type, 2)) {
      this.diags.error(
        node.arguments[0]!,
        'JETH171',
        `bn256Mul(...) requires a G1Point (a @struct of exactly 2 u256 fields), got ${displayName(p.type)}`,
      );
      return undefined;
    }
    if (!isInteger(s.type)) {
      this.diags.error(
        node.arguments[1]!,
        'JETH171',
        `bn256Mul(...) scalar must be an integer, got ${displayName(s.type)}`,
      );
      return undefined;
    }
    return {
      kind: 'bn256',
      type: p.type,
      op: 'mul',
      addr: 7,
      args: [p, this.coerce(s, U256, node.arguments[1]!)],
      insize: 96,
      outsize: 64,
    };
  }

  private checkBlake2fCall(node: ts.CallExpression): Expr | undefined {
    // blake2f(rounds: u32, h: bytes(64), m: bytes(128), t: bytes16, f: bool): bytes (the 64-byte output).
    if (node.arguments.length !== 5) {
      this.diags.error(node, 'JETH170', 'blake2f(...) takes exactly five arguments (rounds, h, m, t, f)');
      return undefined;
    }
    const U32: JethType = { kind: 'uint', bits: 32 };
    const BYTES16: JethType = { kind: 'bytesN', size: 16 };
    const rounds = this.checkExpr(node.arguments[0]!, U32);
    const h = this.checkExpr(node.arguments[1]!, this.bytesLiteralExpected(node.arguments[1]!));
    const m = this.checkExpr(node.arguments[2]!, this.bytesLiteralExpected(node.arguments[2]!));
    const t = this.checkExpr(node.arguments[3]!, BYTES16);
    const f = this.checkExpr(node.arguments[4]!, BOOL);
    if (!rounds || !h || !m || !t || !f) return undefined;
    if (!isInteger(rounds.type)) {
      this.diags.error(
        node.arguments[0]!,
        'JETH171',
        `blake2f(...) rounds must be a u32, got ${displayName(rounds.type)}`,
      );
      return undefined;
    }
    if (h.type.kind !== 'bytes') {
      this.diags.error(
        node.arguments[1]!,
        'JETH171',
        `blake2f(...) h must be bytes (length 64), got ${displayName(h.type)}`,
      );
      return undefined;
    }
    if (m.type.kind !== 'bytes') {
      this.diags.error(
        node.arguments[2]!,
        'JETH171',
        `blake2f(...) m must be bytes (length 128), got ${displayName(m.type)}`,
      );
      return undefined;
    }
    if (t.type.kind !== 'bytesN' || t.type.size !== 16) {
      this.diags.error(node.arguments[3]!, 'JETH171', `blake2f(...) t must be bytes16, got ${displayName(t.type)}`);
      return undefined;
    }
    if (f.type.kind !== 'bool') {
      this.diags.error(
        node.arguments[4]!,
        'JETH171',
        `blake2f(...) f (final-block flag) must be bool, got ${displayName(f.type)}`,
      );
      return undefined;
    }
    return { kind: 'blake2f', type: BYTES, rounds: this.coerce(rounds, U32, node.arguments[0]!), h, m, t, f };
  }

  /** Phase 1 proxies: the EIP-1167 minimal-proxy builtins (byte-identical to OZ Clones 5.1).
   *  - isContract(addr): bool          -> gt(extcodesize(addr), 0); a code read (view-ok, pure-reject).
   *  - clone(impl): address            -> CREATE an EIP-1167 clone; STATE-MUTATING (view/pure reject).
   *  - cloneDeterministic(impl, salt)  -> CREATE2 (same creation code); STATE-MUTATING.
   *  - cloneWithArgs(impl, args)       -> CREATE, modified init returns runtime+args; STATE-MUTATING.
   *  - cloneDeterministicWithArgs(impl, salt, args) -> CREATE2 + args; STATE-MUTATING.
   *  - predictClone(impl, salt): address              -> the CREATE2 address over the exact creation code.
   *  - predictCloneWithArgs(impl, salt, args): address-> same, immutable-args creation code. Reads
   *                                                       address(this) (env): view-ok, pure-reject.
   *  - cloneArgs(): bytes              -> own appended immutable args (own code[0x2d:]); env read. */
  private checkCloneBuiltin(node: ts.CallExpression, callee: string): Expr | undefined {
    const BYTES32: JethType = { kind: 'bytesN', size: 32 };
    // a helper to type-check an address argument (impl / addr); coerces u160/bytes20 -> address.
    const addrArg = (idx: number, who: string): Expr | undefined => {
      const a = this.checkExpr(node.arguments[idx]!, ADDRESS);
      if (!a) return undefined;
      if (a.type.kind === 'address') return a;
      if (this.isAddressConvertible(a.type)) return { kind: 'cast', type: ADDRESS, from: a.type, operand: a };
      this.diags.error(
        node.arguments[idx]!,
        'JETH395',
        `${callee}(...) ${who} must be address, got ${displayName(a.type)}`,
      );
      return undefined;
    };
    const saltArg = (idx: number): Expr | undefined => {
      const s = this.checkExpr(node.arguments[idx]!, BYTES32);
      if (!s) return undefined;
      if (s.type.kind !== 'bytesN' || s.type.size !== 32) {
        this.diags.error(
          node.arguments[idx]!,
          'JETH396',
          `${callee}(...) salt must be bytes32, got ${displayName(s.type)}`,
        );
        return undefined;
      }
      return s;
    };
    const bytesArg = (idx: number): Expr | undefined => {
      const b = this.checkExpr(node.arguments[idx]!, this.bytesLiteralExpected(node.arguments[idx]!));
      if (!b) return undefined;
      if (b.type.kind !== 'bytes') {
        this.diags.error(
          node.arguments[idx]!,
          'JETH397',
          `${callee}(...) args must be bytes, got ${displayName(b.type)} (use bytes(...) / abi.encode(...))`,
        );
        return undefined;
      }
      return b;
    };

    if (callee === 'isContract') {
      if (node.arguments.length !== 1) {
        this.diags.error(node, 'JETH170', 'isContract(...) takes exactly one argument (address)');
        return undefined;
      }
      const addr = addrArg(0, 'address');
      if (!addr) return undefined;
      this.currentReadsEnv = true; // EXTCODESIZE: a view op (forbidden in @pure)
      return { kind: 'isContract', type: BOOL, addr };
    }

    if (callee === 'cloneArgs') {
      if (node.arguments.length !== 0) {
        this.diags.error(node, 'JETH170', 'cloneArgs() takes no arguments');
        return undefined;
      }
      this.currentReadsEnv = true; // EXTCODECOPY of own code: a view op (forbidden in @pure)
      return { kind: 'cloneArgs', type: BYTES };
    }

    if (callee === 'predictClone' || callee === 'predictCloneWithArgs') {
      const withArgs = callee === 'predictCloneWithArgs';
      const want = withArgs ? 3 : 2;
      if (node.arguments.length !== want) {
        this.diags.error(
          node,
          'JETH170',
          `${callee}(...) takes ${want} arguments (${withArgs ? 'impl, salt, args' : 'impl, salt'})`,
        );
        return undefined;
      }
      const impl = addrArg(0, 'impl');
      const salt = saltArg(1);
      if (!impl || !salt) return undefined;
      let args: Expr | undefined;
      if (withArgs) {
        args = bytesArg(2);
        if (!args) return undefined;
      }
      this.currentReadsEnv = true; // reads address(this) (forbidden in @pure)
      return { kind: 'predictClone', type: ADDRESS, impl, salt, args };
    }

    // clone / cloneDeterministic / cloneWithArgs / cloneDeterministicWithArgs: all DEPLOY (CREATE/CREATE2).
    const deterministic = callee === 'cloneDeterministic' || callee === 'cloneDeterministicWithArgs';
    const withArgs = callee === 'cloneWithArgs' || callee === 'cloneDeterministicWithArgs';
    // expected arity: impl [, salt] [, args].
    const want = 1 + (deterministic ? 1 : 0) + (withArgs ? 1 : 0);
    if (node.arguments.length !== want) {
      const sig = ['impl', deterministic ? 'salt' : '', withArgs ? 'args' : ''].filter(Boolean).join(', ');
      this.diags.error(node, 'JETH170', `${callee}(...) takes ${want} arguments (${sig})`);
      return undefined;
    }
    const impl = addrArg(0, 'impl');
    if (!impl) return undefined;
    let salt: Expr | undefined;
    let args: Expr | undefined;
    let next = 1;
    if (deterministic) {
      salt = saltArg(next++);
      if (!salt) return undefined;
    }
    if (withArgs) {
      args = bytesArg(next++);
      if (!args) return undefined;
    }
    // a CREATE/CREATE2 deploy MUTATES state -> reject @view/@pure (matches solc: a deploying fn is nonpayable).
    this.currentWritesState = true;
    return { kind: 'cloneDeploy', type: ADDRESS, impl, salt, args };
  }

  /** Phase 2a proxies: the EIP-1967 upgradeable-proxy foundation builtins (byte-identical to OZ ERC1967).
   *  These are the ONLY way to touch the fixed EIP-1967 slots; the user never writes a raw slot number,
   *  and delegatecall stays unavailable as a free primitive.
   *  - proxyInit(impl, initData)         -> void; require(isContract(impl)); write impl slot; emit Upgraded;
   *  - proxyInit(impl, admin, initData)  -> void; also write the admin slot. STATE-MUTATING (the ctor uses it).
   *  - upgradeProxy(newImpl, data)       -> void; require(isContract); write impl slot; emit Upgraded + run.
   *  - proxyImplementation(): address    -> SLOAD the EIP-1967 impl slot. A storage read (view-ok, pure-reject).
   *  - proxyAdmin(): address             -> SLOAD the EIP-1967 admin slot. A storage read. */
  private checkProxyBuiltin(node: ts.CallExpression, callee: string): Expr | undefined {
    const addrArg = (idx: number, who: string): Expr | undefined => {
      const a = this.checkExpr(node.arguments[idx]!, ADDRESS);
      if (!a) return undefined;
      if (a.type.kind === 'address') return a;
      if (this.isAddressConvertible(a.type)) return { kind: 'cast', type: ADDRESS, from: a.type, operand: a };
      this.diags.error(
        node.arguments[idx]!,
        'JETH395',
        `${callee}(...) ${who} must be address, got ${displayName(a.type)}`,
      );
      return undefined;
    };
    const bytesArg = (idx: number, who: string): Expr | undefined => {
      const b = this.checkExpr(node.arguments[idx]!, this.bytesLiteralExpected(node.arguments[idx]!));
      if (!b) return undefined;
      if (b.type.kind !== 'bytes') {
        this.diags.error(
          node.arguments[idx]!,
          'JETH397',
          `${callee}(...) ${who} must be bytes, got ${displayName(b.type)} (use bytes(...) / abi.encode(...))`,
        );
        return undefined;
      }
      return b;
    };

    if (callee === 'proxyImplementation' || callee === 'proxyAdmin') {
      if (node.arguments.length !== 0) {
        this.diags.error(node, 'JETH170', `${callee}() takes no arguments`);
        return undefined;
      }
      this.currentReadsEnv = true; // SLOAD of a fixed slot: a state read -> forbidden in @pure
      return { kind: 'proxySlotRead', type: ADDRESS, slot: callee === 'proxyAdmin' ? 'admin' : 'impl' };
    }

    // Phase 2d (beacon proxy): proxyBeacon() -> address: SLOAD the EIP-1967 beacon slot. A storage read.
    if (callee === 'proxyBeacon') {
      if (node.arguments.length !== 0) {
        this.diags.error(node, 'JETH170', `${callee}() takes no arguments`);
        return undefined;
      }
      this.currentReadsEnv = true; // SLOAD of the fixed beacon slot: a state read -> forbidden in @pure
      return { kind: 'proxyBeaconRead', type: ADDRESS };
    }

    // Phase 2d (beacon proxy): proxyInitBeacon(beacon, initData): the @proxy('beacon') constructor primitive.
    if (callee === 'proxyInitBeacon') {
      if (node.arguments.length !== 2) {
        this.diags.error(node, 'JETH170', 'proxyInitBeacon(...) takes exactly 2 arguments (beacon, initData)');
        return undefined;
      }
      const beacon = addrArg(0, 'beacon');
      if (!beacon) return undefined;
      const initData = bytesArg(1, 'initData');
      if (!initData) return undefined;
      this.currentWritesState = true; // SSTORE beacon slot + emit + (optional) delegatecall -> reject @view/@pure
      return { kind: 'proxyInitBeacon', type: VOID, beacon, initData };
    }

    if (callee === 'upgradeProxy') {
      if (node.arguments.length !== 2) {
        this.diags.error(node, 'JETH170', 'upgradeProxy(...) takes exactly 2 arguments (newImpl, data)');
        return undefined;
      }
      const impl = addrArg(0, 'newImpl');
      const data = bytesArg(1, 'data');
      if (!impl || !data) return undefined;
      this.currentWritesState = true; // SSTORE + emit + delegatecall -> reject @view/@pure
      return { kind: 'upgradeProxy', type: VOID, impl, data };
    }

    // proxyInit(impl, initData) | proxyInit(impl, admin, initData)
    if (callee === 'proxyInit') {
      if (node.arguments.length !== 2 && node.arguments.length !== 3) {
        this.diags.error(
          node,
          'JETH170',
          'proxyInit(...) takes 2 (impl, initData) or 3 (impl, admin, initData) arguments',
        );
        return undefined;
      }
      const impl = addrArg(0, 'impl');
      if (!impl) return undefined;
      let admin: Expr | undefined;
      let dataIdx = 1;
      if (node.arguments.length === 3) {
        admin = addrArg(1, 'admin');
        if (!admin) return undefined;
        dataIdx = 2;
      }
      const initData = bytesArg(dataIdx, 'initData');
      if (!initData) return undefined;
      this.currentWritesState = true; // SSTORE + emit + delegatecall -> reject @view/@pure
      return { kind: 'proxyInit', type: VOID, impl, admin, initData };
    }
    return undefined;
  }

  /** Phase 3 DIAMOND: the synthesis-only builtins emitted by the @diamond expansion (src/diamond.ts).
   *  Each is only valid inside a synthesized @diamond contract (this.diamond is set); calling one in an
   *  ordinary @contract is a clean JETH414 (the names are double-underscored / reserved).
   *   - diamondInit(owner): void; ctor primitive. Sets contractOwner = owner, registers the 4 ERC-165
   *     interface ids, emits OwnershipTransferred(0, owner). STATE-MUTATING.
   *   - __diamondDelegateInit(_init, _calldata): void; the initializeDiamondCut _init delegatecall (raw
   *     runtime-address delegatecall, bubble the revert). STATE-MUTATING.
   *   - __diamondFacets(): __DiamondFacet[]; the facets() loupe return (raw-Yul builds Facet[] from the
   *     split storage). A storage read. */
  private checkDiamondBuiltin(node: ts.CallExpression, callee: string): Expr | undefined {
    if (!this.diamond) {
      this.diags.error(node, 'JETH414', `'${callee}' is a reserved diamond builtin (only valid inside a @diamond)`);
      return undefined;
    }
    if (callee === 'diamondInit') {
      if (node.arguments.length !== 1) {
        this.diags.error(node, 'JETH414', 'diamondInit(owner) takes exactly one argument (the initial owner)');
        return undefined;
      }
      const a = this.checkExpr(node.arguments[0]!, ADDRESS);
      if (!a) return undefined;
      let owner = a;
      if (a.type.kind !== 'address') {
        if (this.isAddressConvertible(a.type)) owner = { kind: 'cast', type: ADDRESS, from: a.type, operand: a };
        else {
          this.diags.error(
            node.arguments[0]!,
            'JETH414',
            `diamondInit(owner) owner must be address, got ${displayName(a.type)}`,
          );
          return undefined;
        }
      }
      this.currentWritesState = true; // SSTORE owner + the 4 ERC-165 ids + emit -> reject @view/@pure
      return { kind: 'diamondInit', type: VOID, owner };
    }
    if (callee === '__diamondDelegateInit') {
      if (node.arguments.length !== 2) {
        this.diags.error(node, 'JETH414', '__diamondDelegateInit takes exactly 2 arguments');
        return undefined;
      }
      const init = this.checkExpr(node.arguments[0]!, ADDRESS);
      const data = this.checkExpr(node.arguments[1]!, BYTES);
      if (!init || !data) return undefined;
      this.currentWritesState = true; // delegatecall may mutate -> reject @view/@pure
      return { kind: 'diamondDelegateInit', type: VOID, init, data };
    }
    // --- diamond-2 (packed) builtins ---
    if (callee === '__diamondCutPacked') {
      if (node.arguments.length !== 0) {
        this.diags.error(node, 'JETH414', '__diamondCutPacked() takes no arguments');
        return undefined;
      }
      this.currentWritesState = true; // the whole add/replace/remove loop SSTOREs the packed storage
      return { kind: 'diamondCutPacked', type: VOID };
    }
    // --- solidstate builtins ---
    // diamondInitSolidstate(owner): the solidstate @diamond ctor primitive. Sets owner in the Ownable
    // namespace, registers solidstate's ERC-165 interface ids in the ERC165Base namespace, emits
    // OwnershipTransferred(0, owner).
    if (callee === 'diamondInitSolidstate') {
      if (node.arguments.length !== 1) {
        this.diags.error(node, 'JETH414', 'diamondInitSolidstate(owner) takes exactly one argument (the initial owner)');
        return undefined;
      }
      const a = this.checkExpr(node.arguments[0]!, ADDRESS);
      if (!a) return undefined;
      let owner = a;
      if (a.type.kind !== 'address') {
        if (this.isAddressConvertible(a.type)) owner = { kind: 'cast', type: ADDRESS, from: a.type, operand: a };
        else {
          this.diags.error(
            node.arguments[0]!,
            'JETH414',
            `diamondInitSolidstate(owner) owner must be address, got ${displayName(a.type)}`,
          );
          return undefined;
        }
      }
      this.currentWritesState = true;
      return { kind: 'diamondInitSolidstate', type: VOID, owner };
    }
    // __diamondCutSolidstate(): the solidstate diamond-2 add/replace/remove loop (same packing as
    // __diamondCutPacked, but solidstate's custom-error revert set + require order).
    if (callee === '__diamondCutSolidstate') {
      if (node.arguments.length !== 0) {
        this.diags.error(node, 'JETH414', '__diamondCutSolidstate() takes no arguments');
        return undefined;
      }
      this.currentWritesState = true;
      return { kind: 'diamondCutSolidstate', type: VOID };
    }
    // __revertSelector(sel): revert with a bare 4-byte custom-error selector (no ABI args), byte-identical
    // to solc's `revert SomeError()`. The arg must be a compile-time u32 selector literal.
    if (callee === '__revertSelector') {
      if (node.arguments.length !== 1) {
        this.diags.error(node, 'JETH414', '__revertSelector(sel) takes exactly one argument (a u32 selector literal)');
        return undefined;
      }
      const arg = node.arguments[0]!;
      const folded = this.evalConstInt(arg);
      if (folded === undefined || folded < 0n || folded > 0xffffffffn) {
        this.diags.error(arg, 'JETH414', '__revertSelector(sel) requires a constant 4-byte selector literal (0..0xffffffff)');
        return undefined;
      }
      return { kind: 'revertSelector', type: VOID, selector: folded };
    }
    if (callee === '__diamondFacetSelectorsPacked') {
      if (node.arguments.length !== 1) {
        this.diags.error(node, 'JETH414', '__diamondFacetSelectorsPacked(facet) takes exactly one argument');
        return undefined;
      }
      const f = this.checkExpr(node.arguments[0]!, ADDRESS);
      if (!f) return undefined;
      this.currentReadsState = true;
      return {
        kind: 'diamondFacetSelectorsPacked',
        type: { kind: 'array', element: { kind: 'bytesN', size: 4 }, length: undefined },
        facet: f,
      };
    }
    if (callee === '__diamondFacetAddressesPacked') {
      if (node.arguments.length !== 0) {
        this.diags.error(node, 'JETH414', '__diamondFacetAddressesPacked() takes no arguments');
        return undefined;
      }
      this.currentReadsState = true;
      return { kind: 'diamondFacetAddressesPacked', type: { kind: 'array', element: ADDRESS, length: undefined } };
    }
    // __diamondFacets() and __diamondFacetsPacked() both return __DiamondFacet[]
    if (node.arguments.length !== 0) {
      this.diags.error(node, 'JETH414', `${callee}() takes no arguments`);
      return undefined;
    }
    const facetStruct = this.structsByName.get('__DiamondFacet');
    if (!facetStruct || facetStruct.kind !== 'struct') {
      this.diags.error(node, 'JETH414', 'internal: __DiamondFacet struct missing');
      return undefined;
    }
    this.currentReadsState = true; // reads the diamond-storage arrays -> not @pure
    const facetArr: JethType = { kind: 'array', element: facetStruct, length: undefined };
    if (callee === '__diamondFacetsPacked') return { kind: 'diamondFacetsPacked', type: facetArr };
    return { kind: 'diamondFacets', type: facetArr };
  }

  private checkAddressCall(node: ts.CallExpression): Expr | undefined {
    if (node.arguments.length !== 1) {
      this.diags.error(node, 'JETH170', 'address(...) takes exactly one argument');
      return undefined;
    }
    const arg = node.arguments[0]!;
    // address(this) -> the contract's own address (environment read).
    if (arg.kind === ts.SyntaxKind.ThisKeyword) {
      this.currentReadsEnv = true;
      return { kind: 'global', type: ADDRESS, op: 'address' };
    }
    // address(<int literal>) -> address-typed literal (e.g. address(0n)). The EIP-55 checksum / length
    // check still applies to an address-like hex literal inside the cast (solc rejects address(0x<bad>)).
    const lit = this.asIntLiteral(arg);
    if (lit !== undefined) {
      this.rejectUppercaseHexPrefix(arg);
      this.rejectBadUnderscores(arg);
      const addrClass = this.classifyAddressHexLiteral(arg);
      if (addrClass !== 'plain' && addrClass !== 'address') this.diags.error(node, addrClass.code, addrClass.msg);
      if (lit < 0n || lit >= 1n << 160n) {
        this.diags.error(node, 'JETH070', `literal ${lit} out of range for address`);
      }
      return { kind: 'literalInt', type: ADDRESS, value: lit };
    }
    // address(<uint160 | bytes20 | address>) cast.
    const inner = this.checkExpr(arg);
    if (!inner) return undefined;
    if (this.isAddressConvertible(inner.type)) {
      return { kind: 'cast', type: ADDRESS, from: inner.type, operand: inner };
    }
    this.diags.error(
      node,
      'JETH170',
      `explicit conversion to address not allowed from ${displayName(inner.type)} (convert through u160)`,
    );
    return undefined;
  }

  private checkCast(node: ts.CallExpression, callee: string): Expr | undefined {
    if (node.arguments.length !== 1) {
      this.diags.error(node, 'JETH170', `${callee}(...) cast takes exactly one argument`);
      return undefined;
    }
    const arg = node.arguments[0]!;
    if (callee === 'payable') {
      const inner = this.checkExpr(arg);
      if (!inner) return undefined;
      if (inner.type.kind !== 'address') {
        this.diags.error(node, 'JETH171', `payable(...) requires an address operand, got ${displayName(inner.type)}`);
        return undefined;
      }
      return { kind: 'cast', type: { kind: 'address', payable: true }, from: inner.type, operand: inner };
    }
    // an enum conversion `Color(x)`: the operand must be an integer; produce a cast to the enum
    // type whose codegen range-checks `x < memberCount` (Panic 0x21 out of range, solc-identical).
    // A constant operand is range-checked at compile time (solc rejects an out-of-range constant
    // enum conversion at compile time, not at runtime).
    if (this.isEnumName(callee)) {
      const et = this.structsByName.get(callee)! as JethType & { kind: 'uint'; enumMembers: string[] };
      const inner = this.checkExpr(arg);
      if (!inner) return undefined;
      if (!isInteger(inner.type) || isEnum(inner.type)) {
        this.diags.error(
          node,
          'JETH277',
          `enum conversion ${callee}(...) requires an integer operand, got ${displayName(inner.type)}`,
        );
        return undefined;
      }
      if (inner.kind === 'literalInt') {
        if (inner.value < 0n || inner.value >= BigInt(et.enumMembers.length)) {
          this.diags.error(
            node,
            'JETH278',
            `value ${inner.value} is out of range for enum '${callee}' (0..${et.enumMembers.length - 1})`,
          );
          return undefined;
        }
        return { kind: 'literalInt', type: et, value: inner.value };
      }
      return { kind: 'cast', type: et, from: inner.type, operand: inner };
    }

    // a primitive cast (u256(x), address(x), ...) or a branded-newtype wrap (TokenId(x)).
    const target = resolvePrimitiveName(callee) ?? this.structsByName.get(callee)!;
    // bytes(...) / string(...) of a STRING LITERAL: give the literal the target type as expected so it
    // is accepted (e.g. bytes("abc"), string("abc")) instead of failing the no-expected-type gate.
    const argExpected = target && (target.kind === 'bytes' || target.kind === 'string') ? target : undefined;
    const inner = this.checkExpr(arg, argExpected);
    if (!inner) return undefined;
    // An integer-literal cast is range-checked at compile time (uint8(300) is an error
    // in solc, not a runtime truncation): retype the literal to the target directly.
    if (inner.kind === 'literalInt' && isInteger(target)) {
      // an EXPLICIT cast: an enum-member literal may be cast to an integer here (uint256(Color.Blue)).
      const r = this.retypeLiteral(inner, target, node, /* allowEnumToInt */ true);
      if (r) return r;
      // An address-typed literal converts only to uint160 (retypeLiteral returned undefined without a
      // diagnostic); other integer widths are an explicit-conversion error (uint256(0x<addr>)).
      if (inner.type.kind === 'address') {
        this.diags.error(node, 'JETH170', `explicit conversion not allowed from address to ${displayName(target)}`);
      }
      return undefined;
    }
    // bytesN(<int literal>) -> the value LEFT-aligned in the high N bytes (the bytesN register form),
    // matching solc's bytesN literal. (An address-typed literal goes through isCastAllowed: address ->
    // bytes20 only.) e.g. bytes4(0x12345678n) == 0x1234567800...00.
    if (inner.kind === 'literalInt' && target.kind === 'bytesN' && inner.type.kind !== 'address') {
      const v = inner.value;
      // Was the argument an EXPLICIT integer cast `uN(x)`/`iN(x)` (which collapses to a literalInt here)?
      // solc allows `bytesN(uintM(x))` ONLY when the byte sizes match (uint256<->bytes32, ...), a value
      // reinterpret; a different-size uint cast is an explicit-conversion error. This is distinct from a
      // BARE int literal (handled below), which solc restricts to the hex-width rule.
      const stripped = stripParens(arg);
      const argCast =
        ts.isCallExpression(stripped) && ts.isIdentifier(stripped.expression)
          ? resolvePrimitiveName(stripped.expression.text)
          : undefined;
      if (argCast && argCast.kind === 'uint') {
        if (argCast.bits !== target.size * 8) {
          this.diags.error(
            node,
            'JETH170',
            `explicit conversion not allowed from ${displayName(argCast)} to ${displayName(target)}`,
          );
          return undefined;
        }
        return { kind: 'literalInt', type: target, value: v << BigInt((32 - target.size) * 8) };
      }
      // a BARE int literal -> bytesN: solc accepts ONLY the literal 0 (any spelling), or a HEX literal
      // whose source byte width == N. A decimal or wrong-width hex literal is an explicit-conversion error.
      if (v !== 0n && inner.hexBytes !== target.size) {
        this.diags.error(
          node,
          'JETH170',
          `explicit conversion not allowed from integer literal ${v} to ${displayName(target)}`,
        );
        return undefined;
      }
      return { kind: 'literalInt', type: target, value: v << BigInt((32 - target.size) * 8) };
    }
    // an identity conversion is a no-op (e.g. bytes(bytesValue), string(stringValue), or bytes("abc")
    // where the string literal was given the bytes target type above): return the operand unchanged.
    if (typesEqual(inner.type, target)) return inner;
    if (this.isCastAllowed(inner.type, target)) {
      return { kind: 'cast', type: target, from: inner.type, operand: inner };
    }
    this.diags.error(
      node,
      'JETH170',
      `explicit conversion not allowed from ${displayName(inner.type)} to ${displayName(target)}`,
    );
    return undefined;
  }

  private isAddressConvertible(t: JethType): boolean {
    return t.kind === 'address' || (t.kind === 'uint' && t.bits === 160) || (t.kind === 'bytesN' && t.size === 20);
  }

  /** Minimal Phase 3 cast set (each verified against solc): address<->u160 (no-op),
   *  address<->bytes20 (shift). General numeric casts are deferred. */
  private isCastAllowed(from: JethType, to: JethType): boolean {
    // An enum value converts ONLY to an UNSIGNED integer (uintN of any width); solc rejects a
    // direct enum -> intN (must go through `uintN(c)` first) and enum -> bytesN / address / bool.
    // Without this, enum (a branded uint8) would slip through the same-width signed-cast rule below
    // for int8 only. The reverse, integer -> enum, is range-checked in the cast path.
    if ((from as { enumMembers?: string[] }).enumMembers && to.kind !== 'uint') return false;
    if (to.kind === 'uint' && to.bits === 160 && from.kind === 'address') return true;
    if (to.kind === 'bytesN' && to.size === 20 && from.kind === 'address') return true;
    if (to.kind === 'address') return this.isAddressConvertible(from);
    // integer <-> integer: same signedness any size; different signedness ONLY same size
    // (Solidity disallows changing both sign and width in one cast).
    if ((from.kind === 'uint' || from.kind === 'int') && (to.kind === 'uint' || to.kind === 'int')) {
      return from.kind === to.kind || from.bits === to.bits;
    }
    // bool(x) identity self-cast (a no-op; solc accepts bool -> bool).
    if (from.kind === 'bool' && to.kind === 'bool') return true;
    // bytesN <-> bytesM (any size: truncate / zero-pad, left-aligned).
    if (from.kind === 'bytesN' && to.kind === 'bytesN') return true;
    // uintN <-> bytesM of the SAME byte size (uint256<->bytes32, uint32<->bytes4, ...).
    if (from.kind === 'uint' && to.kind === 'bytesN' && from.bits === to.size * 8) return true;
    if (from.kind === 'bytesN' && to.kind === 'uint' && to.bits === from.size * 8) return true;
    // bytes <-> string: a no-op reinterpret of the same dynamic [len][data] value (solc-identical).
    if ((from.kind === 'bytes' && to.kind === 'string') || (from.kind === 'string' && to.kind === 'bytes')) return true;
    // bytesN(bytes): take the first N content bytes (left-aligned), zero-padded if shorter.
    if (from.kind === 'bytes' && to.kind === 'bytesN') return true;
    return false;
  }

  // ---- expressions ---------------------------------------------------------

  private checkExpr(node: ts.Expression, expected?: JethType): Expr | undefined {
    // parenthesized
    if (ts.isParenthesizedExpression(node)) return this.checkExpr(node.expression, expected);

    // assignment used as a value-producing expression: (x = v), (x += v), chained x = y = a.
    // Yields the assigned (LHS-typed) value, exactly like Solidity. Statement-position
    // assignments are handled earlier in checkStatement and never reach here.
    if (ts.isBinaryExpression(node) && this.isAssignmentOperator(node.operatorToken.kind)) {
      return this.checkAssignmentExpr(node);
    }

    // A same-name collision between an @using attached fn and a BUILT-IN member of the SAME receiver
    // type (e.g. lib length(u256[]) vs built-in .length) is ambiguous in solc (rejected). Check
    // BEFORE the built-in member resolvers (.length / .balance / .code / .concat / .slice / external
    // call) so the built-in cannot silently win. A lib fn attached to a DIFFERENT type is not a
    // collision (attachedBuiltinCollision keys on the receiver type).
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      this.libraryAttachments.size > 0 &&
      !(node.expression.expression.kind === ts.SyntaxKind.ThisKeyword) &&
      !(node.expression.expression.kind === ts.SyntaxKind.SuperKeyword)
    ) {
      const recvType = this.trialExprType(node.expression.expression);
      if (
        recvType &&
        this.attachedBuiltinCollision(node, node.expression.expression, recvType, node.expression.name.text)
      ) {
        return undefined;
      }
    }

    // type(T).max / type(T).min -> a compile-time integer constant (Solidity-identical).
    if (
      ts.isPropertyAccessExpression(node) &&
      (node.name.text === 'max' || node.name.text === 'min') &&
      ts.isCallExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === 'type' &&
      node.expression.arguments.length === 1 &&
      ts.isIdentifier(node.expression.arguments[0]!)
    ) {
      const argName = (node.expression.arguments[0] as ts.Identifier).text;
      if (this.isEnumName(argName)) {
        const et = this.structsByName.get(argName)! as JethType & { kind: 'uint'; enumMembers: string[] };
        return {
          kind: 'literalInt',
          type: et,
          value: node.name.text === 'max' ? BigInt(et.enumMembers.length - 1) : 0n,
        };
      }
      const t = resolvePrimitiveName(argName);
      if (!t || !isInteger(t)) {
        this.diags.error(node, 'JETH074', 'type(T).max/.min requires an integer type T');
        return undefined;
      }
      const isMax = node.name.text === 'max';
      const bits = t.kind === 'uint' ? t.bits : (t as { kind: 'int'; bits: number }).bits;
      const value =
        t.kind === 'uint'
          ? isMax
            ? (1n << BigInt(bits)) - 1n
            : 0n
          : isMax
            ? (1n << BigInt(bits - 1)) - 1n
            : -(1n << BigInt(bits - 1));
      return { kind: 'literalInt', type: t, value };
    }

    // function `.selector` -> the 4-byte ABI selector, a compile-time bytes4 constant (left-aligned in
    // the high 4 bytes, exactly like abi.encodeWithSelector's literal). solc allows it on an EXTERNAL/
    // PUBLIC function reference (`this.f.selector`, or a bare `f.selector`); an internal/private function
    // has no ABI selector. Scoped to an unambiguous (non-overloaded) function name.
    if (ts.isPropertyAccessExpression(node) && node.name.text === 'selector') {
      let fnName: string | undefined;
      if (
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.expression.kind === ts.SyntaxKind.ThisKeyword
      ) {
        fnName = node.expression.name.text; // this.f.selector
      } else if (ts.isIdentifier(node.expression) && !this.isVisibleLocal(node.expression.text)) {
        fnName = node.expression.text; // bare f.selector (not shadowed by a local)
      }
      if (fnName !== undefined) {
        const sel = this.functionSelectorOf(node, fnName);
        if (sel) return sel;
        // fnName matched a function name but was ambiguous/internal: a diagnostic was emitted.
        if (this.candidatesByName.has(fnName)) return undefined;
        // not a function name at all: fall through to the normal property-access handling/error.
      }
    }

    // enum member access `Color.Red` -> a compile-time uint8 constant of the enum type with the
    // member's declaration index. An enum name is a TYPE name (never a local/state/global), so an
    // identifier base that names an enum is unambiguous; fire before every other property-access
    // interpretation. (`Color` standing alone is not a value, only `Color.Member`.)
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isIdentifier(node.expression) &&
      this.isEnumName(node.expression.text)
    ) {
      const et = this.structsByName.get(node.expression.text)! as JethType & { kind: 'uint'; enumMembers: string[] };
      const idx = et.enumMembers.indexOf(node.name.text);
      if (idx < 0) {
        this.diags.error(node, 'JETH271', `enum '${node.expression.text}' has no member '${node.name.text}'`);
        return undefined;
      }
      return { kind: 'literalInt', type: et, value: BigInt(idx) };
    }

    // ternary c ? a : b -> the common type of the two branches (short-circuit at codegen).
    if (ts.isConditionalExpression(node)) {
      const cond = this.checkCondition(node.condition);
      const then = this.checkExpr(node.whenTrue, expected);
      const els = this.checkExpr(node.whenFalse, expected);
      if (!cond || !then || !els) return undefined;
      // unify the branch types (literal retyping / widening to a common type).
      const unified = this.unifyOperands(then, els, node);
      if (!unified) {
        this.diags.error(
          node,
          'JETH083',
          `ternary branches have incompatible types: ${displayName(then.type)} vs ${displayName(els.type)}`,
        );
        return undefined;
      }
      // A DYNAMIC value-element array ternary (c ? a : b, incl. storage `this.a`/`this.b`): materialize
      // the TAKEN branch to a memory [len][elems] pointer (codegen, via aggArgToMemPtr - storage/
      // calldata copy, memory alias) and select it; wrap as a memArrayExpr so return / index /
      // .length consume it uniformly. Matches solc (only the taken branch is read; identical bytes).
      const ut = unified[0].type;
      if (ut.kind === 'array' && ut.length === undefined && isStaticValueType(ut.element)) {
        const dynArrOk = (e: Expr): boolean =>
          e.kind === 'arrayLit' ||
          e.kind === 'newArray' || // new Array<T>(n): a fresh [len][elems] memory pointer (mem location)
          (e.kind === 'arrayValue' &&
            (e.arr.base.kind === 'memArray' ||
              e.arr.base.kind === 'memArrayExpr' ||
              e.arr.base.kind === 'stateArray' ||
              e.arr.base.kind === 'mapArray' ||
              e.arr.base.kind === 'placeArray' ||
              e.arr.base.kind === 'calldataArray'));
        if (dynArrOk(unified[0]) && dynArrOk(unified[1])) {
          // Match solc's data-location rules: storage|calldata is a hard type error, and
          // calldata|calldata yields a CALLDATA reference (an indexed read VALIDATES dirty elements)
          // which our materialize-to-memory (masking) does not replicate - gate both. memory|*,
          // storage|storage, and storage|memory all reduce to a memory image (byte-identical reads).
          const loc = (e: Expr): 'cd' | 'storage' | 'mem' =>
            e.kind === 'arrayValue' && e.arr.base.kind === 'calldataArray'
              ? 'cd'
              : e.kind === 'arrayValue' &&
                  (e.arr.base.kind === 'stateArray' ||
                    e.arr.base.kind === 'mapArray' ||
                    e.arr.base.kind === 'placeArray')
                ? 'storage'
                : 'mem';
          const l0 = loc(unified[0]),
            l1 = loc(unified[1]);
          if ((l0 === 'cd' && l1 === 'cd') || (l0 === 'cd' && l1 === 'storage') || (l0 === 'storage' && l1 === 'cd')) {
            this.diags.error(
              node,
              'JETH074',
              `a ternary mixing a calldata array with a calldata/storage array (data-location mismatch) is not supported; copy a branch to a memory local first`,
            );
            return undefined;
          }
          const tern: Expr = { kind: 'ternary', type: ut, cond, then: unified[0], else: unified[1] };
          return {
            kind: 'arrayValue',
            type: ut,
            arr: { base: { kind: 'memArrayExpr', expr: tern }, elem: ut.element },
          };
        }
        this.diags.error(
          node,
          'JETH074',
          `a ternary over a ${displayName(ut)} from this source is not supported; select the value before the aggregate operation`,
        );
        return undefined;
      }
      // A ternary branch must lower to a single register value (a value type, or a MEMORY array
      // whose register IS its pointer), OR be a bytes/string (materialized to memory and selected
      // by pointer via lowerDynamic). A storage struct / a non-value-element array branch still has
      // no single materialization here, so select before the aggregate operation.
      const lowerable = (e: Expr): boolean =>
        isStaticValueType(e.type) ||
        isBytesLike(e.type) ||
        // a STATIC struct / fixed array: materialized to a memory image, selected by pointer.
        (isStaticType(e.type) &&
          (e.type.kind === 'struct' || (e.type.kind === 'array' && e.type.length !== undefined))) ||
        // a DYNAMIC-field struct: materialized to a pointer-headed memory image (buildDynStructLocal)
        // and selected by pointer; the ternary result re-encodes via the mem TupleSrc. Branch sources
        // are exactly the kinds buildDynStructLocal copies (constructor / mem local / calldata param /
        // storage struct sources).
        (e.type.kind === 'struct' &&
          isDynamicType(e.type) &&
          (e.kind === 'memDynStructValue' ||
            e.kind === 'structNew' ||
            e.kind === 'cdDynStructValue' ||
            e.kind === 'structValue' ||
            e.kind === 'mapStorageValue' ||
            e.kind === 'structArrayElem' ||
            e.kind === 'placeRead')) ||
        (e.type.kind === 'array' &&
          (e.kind === 'arrayLit' ||
            (e.kind === 'arrayValue' && (e.arr.base.kind === 'memArray' || e.arr.base.kind === 'memArrayExpr'))));
      if (!lowerable(unified[0]) || !lowerable(unified[1])) {
        this.diags.error(
          node,
          'JETH074',
          `a ternary over a ${displayName(unified[0].type)} (dynamic storage aggregate) is not supported; select the value before the aggregate operation`,
        );
        return undefined;
      }
      return { kind: 'ternary', type: unified[0].type, cond, then: unified[0], else: unified[1] };
    }

    // A (possibly negated) integer literal folds to a single signed literal, so
    // the range check sees the real value: `-128n` is a valid i8 (== INT_MIN),
    // not "128 out of range". `-x` on a non-literal still uses checked negation.
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.MinusToken) {
      const folded = this.asIntLiteral(node);
      if (folded !== undefined) {
        if (this.rejectBadUnderscores(node))
          return { kind: 'literalInt', type: folded < 0n ? I256 : U256, value: folded };
        // an enum `expected` does NOT capture a bare integer literal: it keeps its plain int type
        // so coerce rejects the implicit int -> enum (solc forbids `Color c = 1;`).
        const type = expected && isInteger(expected) && !isEnum(expected) ? expected : folded < 0n ? I256 : U256;
        if (!this.inRange(folded, type)) {
          this.diags.error(node, 'JETH070', `literal ${folded} out of range for ${displayName(type)}`);
        }
        return { kind: 'literalInt', type, value: folded };
      }
    }

    // BigInt literal -> integer
    if (ts.isBigIntLiteral(node)) {
      const raw = node.text.replace(/n$/, '');
      const value = BigInt(raw);
      // a HEX literal carries its source byte width (digits / 2, even-digit only) for bytesN conversion.
      const hexDigits = /^0x/i.test(raw) ? raw.length - 2 : -1;
      const hexBytes = hexDigits >= 0 && hexDigits % 2 === 0 ? hexDigits / 2 : undefined;
      if (this.rejectUppercaseHexPrefix(node)) return { kind: 'literalInt', type: U256, value, hexBytes };
      if (this.rejectBadUnderscores(node)) return { kind: 'literalInt', type: U256, value, hexBytes };
      // A 40-hex-digit checksummed literal is of type `address` (and only converts to uint160/bytes20,
      // never implicitly to an integer); a 39/41-digit or bad-checksum hex literal is a hard error.
      const addrClass = this.classifyAddressHexLiteral(node);
      if (addrClass === 'address') {
        return { kind: 'literalInt', type: ADDRESS, value };
      }
      if (addrClass !== 'plain') {
        this.diags.error(node, addrClass.code, addrClass.msg);
        return { kind: 'literalInt', type: U256, value, hexBytes };
      }
      // solc implicitly converts a hex literal to bytesN iff its source byte width == N (left-aligned in
      // the high N bytes). e.g. `bytes4 b = 0x12345678` -> 0x1234567800..00. A shorter/longer hex
      // literal, or a decimal literal, does NOT convert (only the literal 0 does, handled in coerce).
      if (expected && expected.kind === 'bytesN' && hexBytes === expected.size) {
        return { kind: 'literalInt', type: expected, value: value << BigInt((32 - expected.size) * 8) };
      }
      // an enum `expected` does NOT capture a bare integer literal (see the negated-literal case
      // above): keep the plain int type so coerce rejects the implicit int -> enum.
      const type = expected && isInteger(expected) && !isEnum(expected) ? expected : U256;
      if (!this.inRange(value, type)) {
        this.diags.error(node, 'JETH070', `literal ${value} out of range for ${displayName(type)}`);
      }
      return { kind: 'literalInt', type, value, hexBytes };
    }

    // numeric literal (no 'n') -> error: must use BigInt
    if (ts.isNumericLiteral(node)) {
      this.diags.error(node, 'JETH071', `use a BigInt literal (${node.text}n) - JETH integers are BigInt`);
      return undefined;
    }

    // boolean
    if (node.kind === ts.SyntaxKind.TrueKeyword) return { kind: 'literalBool', type: BOOL, value: true };
    if (node.kind === ts.SyntaxKind.FalseKeyword) return { kind: 'literalBool', type: BOOL, value: false };

    // string/bytes literal -> a memory dynamic value (only where bytes/string expected)
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      if (expected && isBytesLike(expected)) {
        return { kind: 'stringLiteral', type: expected, bytes: new TextEncoder().encode(node.text) };
      }
      this.diags.error(node, 'JETH074', 'a string literal is only valid where a string/bytes value is expected');
      return undefined;
    }

    // template literal `Hello ${name}` -> string.concat of the cooked parts + interpolated string exprs.
    if (ts.isTemplateExpression(node)) return this.checkTemplateLiteral(node);

    // <array | bytes>.length -> u256
    if (
      ts.isPropertyAccessExpression(node) &&
      node.name.text === 'length' &&
      node.expression.kind !== ts.SyntaxKind.ThisKeyword
    ) {
      const bt = this.baseDynType(node.expression);
      // an @using lib fn named `length` attached to the receiver's array/bytes type collides with the
      // built-in `.length` (solc: "Member length not unique after argument-dependent lookup"). Reject
      // the PROPERTY form too - the call form `a.length()` is already gated at the attached-call dispatch.
      if (bt && this.attachedBuiltinCollision(node, node.expression, bt, 'length')) return undefined;
      // a fixed array's length is a compile-time constant (state or calldata param)
      if (bt && bt.kind === 'array' && bt.length !== undefined) {
        return { kind: 'literalInt', type: U256, value: BigInt(bt.length) };
      }
      // dynamic array length (state, calldata param, or mapping value this.m[k])
      const lenArr = this.resolveArrayExpr(node.expression);
      if (lenArr) {
        if (lenArr.base.kind === 'fixedArray')
          return { kind: 'literalInt', type: U256, value: BigInt(lenArr.base.length) };
        // storage-backed arrays (stateArray / mapArray) read state; calldata sources
        // (calldataArray / cdNestedElem) do not.
        if (lenArr.base.kind === 'stateArray' || lenArr.base.kind === 'mapArray') this.currentReadsState = true;
        return { kind: 'arrayLen', type: U256, arr: lenArr };
      }
      // s.xs.length: a dynamic value-array field of a calldata dynamic-struct param (runtime length
      // from the array's tail). Only fires for an array field; a bytes/struct field falls through.
      if (ts.isPropertyAccessExpression(node.expression)) {
        const dyn = this.resolveCdDynStruct(node.expression);
        if (dyn && dyn.result && dyn.result.kind === 'arrayValue' && dyn.result.arr.base.kind === 'cdDynArrayField') {
          return { kind: 'arrayLen', type: U256, arr: dyn.result.arr };
        }
        // an inline fixed-array field (s.xs where xs: Arr<T,N>): .length is the compile-time constant N.
        if (dyn && dyn.result && dyn.result.kind === 'arrayValue' && dyn.result.arr.base.kind === 'cdDynFixedField') {
          return { kind: 'literalInt', type: U256, value: BigInt(dyn.result.arr.base.length) };
        }
        if (dyn && !dyn.result) return undefined; // committed but errored (diagnostic already emitted)
      }
      // ds[i].xs.length: a dynamic value-array FIELD of a calldata dynamic-struct ARRAY element
      // (e.g. _diamondCut[i].functionSelectors.length). The element ds[i] is reached via the
      // per-element offset table, then the field's array decodes to (start,len). Reuse the SAME
      // resolver the indexed read ds[i].xs[j] uses (resolveCdDynArrayField -> a cdDynArrayField
      // arrayValue), then read its length word - byte-identical to the working element path.
      if (ts.isPropertyAccessExpression(node.expression) && ts.isElementAccessExpression(node.expression.expression)) {
        const bt = this.baseDynType(node.expression.expression.expression);
        if (bt && bt.kind === 'array' && bt.element.kind === 'struct' && isDynamicType(bt.element)) {
          const av = this.resolveCdDynArrayField(node.expression, bt.element);
          if (av && av.kind === 'arrayValue' && av.arr.base.kind === 'cdDynArrayField') {
            return { kind: 'arrayLen', type: U256, arr: av.arr };
          }
          if (!av) return undefined; // committed but errored
        }
      }
      // .length of a fixed-array field/element of a calldata aggregate param: a
      // compile-time constant (e.g. s.data.length where data: Arr<T,N>).
      const cdType = this.calldataAccessType(node.expression);
      if (cdType && cdType.kind === 'array' && cdType.length !== undefined) {
        return { kind: 'literalInt', type: U256, value: BigInt(cdType.length) };
      }
      if (bt && bt.kind === 'array') return undefined; // array but unresolvable -> no diagnostic doubling
      const operand = this.checkExpr(node.expression);
      if (!operand) return undefined;
      if (operand.type.kind === 'bytesN') {
        // a fixed-bytes value: .length is the compile-time constant N (solc: bytesN(x).length == N).
        return { kind: 'literalInt', type: U256, value: BigInt(operand.type.size) };
      }
      if (operand.type.kind === 'string') {
        this.diags.error(node, 'JETH202', "'string' has no .length in Solidity; only 'bytes' does");
        return undefined;
      }
      if (operand.type.kind !== 'bytes') {
        this.diags.error(node, 'JETH202', `.length is not valid on ${displayName(operand.type)}`);
        return undefined;
      }
      return { kind: 'dynLength', type: U256, operand };
    }

    // new Array<T>(n) -> a length-n zero-initialized dynamic memory array T[] (byte-identical to solc
    // new T[](n)). The element T must be a value type; the length is a runtime u256.
    if (ts.isNewExpression(node)) {
      if (!ts.isIdentifier(node.expression) || node.expression.text !== 'Array') {
        // every other `new` is rejected by the subset validator (JETH023); do not double-report.
        return undefined;
      }
      if (!node.typeArguments || node.typeArguments.length !== 1) {
        this.diags.error(
          node,
          'JETH363',
          'new Array<T>(n) requires exactly one element-type argument, e.g. new Array<u256>(n)',
        );
        return undefined;
      }
      if (!node.arguments || node.arguments.length !== 1) {
        this.diags.error(node, 'JETH363', 'new Array<T>(n) takes exactly one length argument, e.g. new Array<u256>(n)');
        return undefined;
      }
      const elem = resolveType(node.typeArguments[0]!, this.diags, this.structsByName);
      if (!elem) return undefined;
      if (!isStaticValueType(elem)) {
        this.diags.error(
          node.typeArguments[0]!,
          'JETH216',
          `new Array<T>(n) requires a value-type element (uint/int/bool/address/bytesN/enum); a ${displayName(elem)} element is not supported`,
        );
        return undefined;
      }
      const lenRaw = this.checkExpr(node.arguments[0]!, U256);
      if (!lenRaw) return undefined;
      if (!isInteger(lenRaw.type)) {
        this.diags.error(
          node.arguments[0]!,
          'JETH363',
          `new Array<T>(n) length must be an integer, got ${displayName(lenRaw.type)}`,
        );
        return undefined;
      }
      const length = this.coerce(lenRaw, U256, node.arguments[0]!);
      const arrTy: JethType = { kind: 'array', element: elem };
      return { kind: 'newArray', type: arrTy, elem, length };
    }

    // array literal [a, b, c] -> memory T[] (only where an array type is expected)
    if (ts.isArrayLiteralExpression(node)) {
      if (!expected || expected.kind !== 'array') {
        this.diags.error(node, 'JETH213', 'cannot infer array-literal type here (expected an array type)');
        return undefined;
      }
      // Only a 1-D dynamic array literal of value-type elements is supported. A dynamic array
      // literal whose elements are themselves dynamic/aggregate (e.g. u256[][], string[], S[],
      // Arr<u256,2>[]) is rejected: the return/copy encoder cannot represent it (solc likewise
      // rejects these literals, which type as fixed T[N] and don't convert to a dynamic array).
      if (expected.length === undefined && !isStaticValueType(expected.element)) {
        this.diags.error(
          node,
          'JETH216',
          `a dynamic array literal must have value-type elements; a literal of ${displayName(expected.element)} elements is not supported`,
        );
        return undefined;
      }
      // a FIXED array Arr<T,N> literal must have EXACTLY N elements; solc rejects a count
      // mismatch (it never implicitly pads or truncates). A dynamic T[] literal takes any count.
      if (expected.length !== undefined && node.elements.length !== expected.length) {
        this.diags.error(
          node,
          'JETH226',
          `fixed-array literal must have exactly ${expected.length} element(s) for ${displayName(expected)} (got ${node.elements.length})`,
        );
        return undefined;
      }
      const elements: Expr[] = [];
      for (const el of node.elements) {
        const e = this.checkExpr(el, expected.element);
        if (!e) return undefined;
        elements.push(this.coerce(e, expected.element, el));
      }
      return { kind: 'arrayLit', type: expected, elem: expected.element, elements };
    }

    // `d.field` read on a DYNAMIC-field struct memory local: a value field -> a memory load
    // (memField at the head word); a bytes/string field -> the head word holds the [len][data]
    // pointer (memDynField, routed through the bytes/string codec). Must precede the resolvers below.
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isIdentifier(node.expression) &&
      this.memDynStructLocals.has(node.expression.text)
    ) {
      const mf = this.memDynStructField(node);
      if (!mf) return undefined;
      if (isStaticValueType(mf.field.type))
        return { kind: 'memField', type: mf.field.type, local: mf.local, wordOffset: mf.headWord };
      // a dynamic value-array field: the head word holds a pointer to [len][elems]. Wrap a head-word
      // LOAD (memField) in memArrayExpr so index / .length / return consume it as a memory array.
      if (mf.field.type.kind === 'array' && mf.field.type.length === undefined) {
        const load: Expr = { kind: 'memField', type: U256, local: mf.local, wordOffset: mf.headWord };
        return {
          kind: 'arrayValue',
          type: mf.field.type,
          arr: { base: { kind: 'memArrayExpr', expr: load }, elem: mf.field.type.element },
        };
      }
      return { kind: 'memDynField', type: mf.field.type, local: mf.local, wordOffset: mf.headWord };
    }
    // `this.mk(a).x` / `mk(a).x`: member access whose BASE is a struct-returning internal call.
    // solc materializes the call result to a memory struct and reads the field. We do the same: a
    // struct-returning `call` Expr lowers to its pointer-headed memory image, then mload at the
    // field's word offset (aggFieldRead). Scoped to a STATIC struct return with a VALUE final field
    // (a nested struct / non-value field is the existing memory-struct-field gate, left deferred).
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isCallExpression(node.expression) &&
      !this.memChainRoot(node) &&
      node.expression.expression.kind !== ts.SyntaxKind.SuperKeyword
    ) {
      // Peek the base call's type (rolled back) before committing, so a non-struct call falls through
      // to the normal resolvers without a duplicate diagnostic or leaked effect flags.
      const bt = this.trialExprType(node.expression);
      if (bt && bt.kind === 'struct' && isStaticType(bt)) {
        const base = this.checkExpr(node.expression);
        if (!base) return undefined;
        if (base.kind !== 'call') {
          // a struct VALUE that is not a fresh internal-call result (alias/storage source) reached
          // here is unexpected; fall through to the normal handlers rather than mishandle it.
        } else {
          const fo = this.memFieldOffset(bt, node.name.text);
          if (!fo) {
            this.diags.error(node, 'JETH210', `struct '${bt.name}' has no field '${node.name.text}'`);
            return undefined;
          }
          if (!isStaticValueType(fo.type)) {
            this.diags.error(
              node,
              'JETH245',
              `reading a ${displayName(fo.type)} field of a struct-returning call result is not supported yet (bind the call to a local first)`,
            );
            return undefined;
          }
          return { kind: 'aggFieldRead', type: fo.type, base, wordOffset: fo.wordOffset };
        }
      }
    }
    // G9: `p.x` / `p.inner.x` / `p.inner` read where the chain is rooted at a memory-aggregate
    // (struct) local. A VALUE final field -> a memory load (memField); a whole nested STRUCT
    // field -> a sub-pointer into the parent image (memAggregate at the field offset, which
    // aliases the parent). Must precede the calldata/storage access resolvers below.
    if (ts.isPropertyAccessExpression(node) && this.memChainRoot(node)) {
      const r = this.resolveMemFieldChain(node);
      if (!r) return undefined;
      if (isStaticValueType(r.type))
        return { kind: 'memField', type: r.type, local: r.local, wordOffset: r.wordOffset };
      if (r.type.kind === 'struct')
        return { kind: 'memAggregate', type: r.type, local: r.local, wordOffset: r.wordOffset };
      this.diags.error(
        node,
        'JETH245',
        `reading a ${displayName(r.type)} field of a memory struct is not supported yet`,
      );
      return undefined;
    }
    // G9: a[i] on a fixed-array MEMORY local (value element) -> a bounds-checked memory load.
    // Must precede the calldata/storage access resolvers below.
    if (ts.isElementAccessExpression(node) && ts.isIdentifier(node.expression) && node.argumentExpression) {
      const at = this.memAggregateLocals.get(node.expression.text);
      if (at && at.kind === 'array' && at.length !== undefined) {
        const index = this.checkExpr(node.argumentExpression, U256);
        if (!index) return undefined;
        const idx = this.coerce(index, U256, node.argumentExpression);
        if (!this.checkMemElemBound(idx, at.length, node.argumentExpression)) return undefined;
        return { kind: 'memElem', type: at.element, local: node.expression.text, index: idx, length: at.length };
      }
    }
    // G9: p.a[i] where a is a fixed-array VALUE field of a memory struct local -> memElem at a's word
    // offset within the image (the element words are inline, one per element).
    if (
      ts.isElementAccessExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.argumentExpression &&
      this.memChainRoot(node.expression)
    ) {
      const fld = this.resolveMemFieldChain(node.expression);
      if (fld && fld.type.kind === 'array' && fld.type.length !== undefined && isStaticValueType(fld.type.element)) {
        const index = this.checkExpr(node.argumentExpression, U256);
        if (!index) return undefined;
        const idx = this.coerce(index, U256, node.argumentExpression);
        if (!this.checkMemElemBound(idx, fld.type.length, node.argumentExpression)) return undefined;
        return {
          kind: 'memElem',
          type: fld.type.element,
          local: fld.local,
          index: idx,
          length: fld.type.length,
          wordOffset: fld.wordOffset,
        };
      }
    }

    // nested storage access: this.s.f, this.pts[i].x, this.m[k].f, this.m[r][c]
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const acc = this.resolveAccess(node);
      if (acc) {
        if (!acc.result) return undefined; // committed but errored
        this.currentReadsState = true;
        // A bytes/string leaf (a storage dynamic-struct field) is a dynamic value,
        // not a packed-word read: emit dynPlaceRead so the storage bytes/string
        // codec materializes it (return / .length / [i]).
        if (isBytesLike(acc.result.finalType)) {
          return { kind: 'dynPlaceRead', type: acc.result.finalType, path: acc.result.path };
        }
        return { kind: 'placeRead', type: acc.result.finalType, path: acc.result.path };
      }
      // dynamic-struct calldata param: d.field (static leaf or bytes/string field)
      const dyn = this.resolveCdDynStruct(node);
      if (dyn) return dyn.result;
      // aggregate calldata param: s.field, a[i], a[i].field, s.sub[j] (read)
      const cd = this.resolveCalldataPlace(node);
      if (cd) {
        if (!cd.result) return undefined; // committed but errored
        return { kind: 'cdPlaceRead', type: cd.result.finalType, place: cd.result.place };
      }
      // dynamic-array-of-struct calldata param element field: ps[i].field
      if (ts.isPropertyAccessExpression(node) && ts.isElementAccessExpression(node.expression)) {
        const bt = this.baseDynType(node.expression.expression);
        if (bt && bt.kind === 'array' && bt.element.kind === 'struct') {
          // a DYNAMIC-struct array element field (D[] or Arr<D,N>): tuple via the
          // offset table. A STATIC-struct DYNAMIC array (Pt[], 4e-1): inline element.
          if (isDynamicType(bt.element)) return this.resolveCdDynArrayField(node, bt.element);
          if (bt.length === undefined) return this.resolveCdArrayField(node, bt.element);
          // Arr<staticStruct,N>: owned by resolveCalldataPlace (cdAggregates) above.
        }
      }
      // deeper static field chain off a dynamic array element: ps[i].inn.v. The outer
      // `.v` has a PropertyAccessExpression base (ps[i].inn), so the one-deep matcher
      // above misses it. Peel the property accesses to the underlying `arr[i]`; if the
      // array is a DYNAMIC array of a STATIC struct, the element (and every nested
      // static struct) is inline, so resolveCdArrayField reads the leaf at a fixed word.
      if (ts.isPropertyAccessExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        let inner: ts.Expression = node.expression;
        while (ts.isPropertyAccessExpression(inner)) inner = inner.expression;
        if (ts.isElementAccessExpression(inner)) {
          const bt = this.baseDynType(inner.expression);
          if (
            bt &&
            bt.kind === 'array' &&
            bt.length === undefined &&
            bt.element.kind === 'struct' &&
            isStaticType(bt.element)
          ) {
            return this.resolveCdArrayField(node, bt.element);
          }
        }
      }
    }

    // this.struct.field (struct field read)
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.expression.kind === ts.SyntaxKind.ThisKeyword
    ) {
      const sv = this.stateByName.get(node.expression.name.text);
      if (sv && sv.type.kind === 'struct') {
        const f = sv.type.fields.find((ff) => ff.name === node.name.text);
        if (!f) {
          this.diags.error(node, 'JETH210', `struct '${sv.type.name}' has no field '${node.name.text}'`);
          return undefined;
        }
        // this.d.s read: a bytes/string field of a storage dynamic struct -> a
        // dynamic value at sv.slot + f.slot (re-encoded as a standalone top-level
        // value on return, or .length / [i]).
        if (isBytesLike(f.type)) {
          this.currentReadsState = true;
          return {
            kind: 'dynPlaceRead',
            type: f.type,
            path: {
              baseSlot: sv.slot,
              steps: [{ kind: 'field', fieldSlot: f.slot, fieldOffset: f.offset, fieldType: f.type }],
            },
          };
        }
        // return this.o.inner: a whole nested-struct field, encoded from its slot by the
        // storage-source encoder (structValue reuses the whole-struct return machinery).
        if (f.type.kind === 'struct') {
          this.currentReadsState = true;
          return { kind: 'structValue', type: f.type, baseSlot: sv.slot + BigInt(f.slot) };
        }
        // return this.s.xs: a whole array field. A DYNAMIC array field is a placeArray
        // (length at the field slot); a FIXED array field is a static aggregate at the
        // field's constant slot. Both encoded from storage on return.
        if (f.type.kind === 'array') {
          this.currentReadsState = true;
          if (f.type.length === undefined) {
            return {
              kind: 'arrayValue',
              type: f.type,
              arr: {
                base: {
                  kind: 'placeArray',
                  path: {
                    baseSlot: sv.slot,
                    steps: [{ kind: 'field', fieldSlot: f.slot, fieldOffset: f.offset, fieldType: f.type }],
                  },
                },
                elem: f.type.element,
              },
            };
          }
          return {
            kind: 'arrayValue',
            type: f.type,
            arr: {
              base: { kind: 'fixedArray', baseSlot: sv.slot + BigInt(f.slot), length: f.type.length },
              elem: f.type.element,
            },
          };
        }
        if (!isStaticValueType(f.type)) {
          this.diags.error(node, 'JETH226', 'nested array field access is not supported yet');
          return undefined;
        }
        this.currentReadsState = true;
        return {
          kind: 'stateRead',
          type: f.type,
          slot: sv.slot + BigInt(f.slot),
          offset: f.offset,
          varName: `${sv.name}.${f.name}`,
        };
      }
    }

    // Phase 6: `this.ok` / `this.data` scoped bindings inside a .call/.staticcall success condition.
    // Resolved BEFORE constant/immutable/state lookup so they take precedence (and never leak outside
    // the condition: callResultBindings is set only while checking it). Any OTHER `this.<x>` inside a
    // condition still resolves normally (state/constant/immutable) via the guards below.
    if (
      this.callResultBindings &&
      ts.isPropertyAccessExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ThisKeyword &&
      this.callResultBindings.has(node.name.text)
    ) {
      const t = this.callResultBindings.get(node.name.text)!;
      return node.name.text === 'ok' ? { kind: 'callOk', type: t } : { kind: 'callData', type: t };
    }

    // Feature 2: `this.reason` / `this.panic` scoped bindings inside a try/catch CATCH body. Resolved
    // BEFORE constant/immutable/state lookup so they take precedence; never leak (set only while checking
    // the catch body). Record usage so codegen only computes the one(s) actually read.
    if (
      this.catchBindings &&
      ts.isPropertyAccessExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ThisKeyword &&
      this.catchBindings.has(node.name.text)
    ) {
      const t = this.catchBindings.get(node.name.text)!;
      if (node.name.text === 'reason') {
        this.catchUsesReason = true;
        return { kind: 'catchReason', type: t };
      }
      this.catchUsesPanic = true;
      return { kind: 'catchPanic', type: t };
    }

    // this.CONSTANT (read): inline the folded literal (no SLOAD; @constant is slot-free, like solc).
    if (
      ts.isPropertyAccessExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ThisKeyword &&
      this.constantsByName.has(node.name.text)
    ) {
      const c = this.constantsByName.get(node.name.text)!;
      if (c.value instanceof Uint8Array) return { kind: 'stringLiteral', type: c.type, bytes: c.value }; // string constant
      return typeof c.value === 'boolean'
        ? { kind: 'literalBool', type: c.type, value: c.value }
        : { kind: 'literalInt', type: c.type, value: c.value };
    }

    // this.<immutable> (read). An immutable read is a code read (loadimmutable), NOT a storage read,
    // but solc still requires `view` (rejects `pure`): it "reads the environment". Inside the
    // constructor body the read is the STAGED shadow (value assigned so far); elsewhere it lowers to
    // a runtime loadimmutable.
    if (
      ts.isPropertyAccessExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ThisKeyword &&
      this.immutablesByName.has(node.name.text)
    ) {
      const im = this.immutablesByName.get(node.name.text)!;
      this.currentReadsEnv = true; // forbidden in @pure, allowed in @view (matches solc)
      return this.currentInConstructor
        ? { kind: 'immutableStagedRead', type: im.type, name: im.name }
        : { kind: 'immutableRead', type: im.type, name: im.name };
    }

    // this.stateVar (read)
    if (ts.isPropertyAccessExpression(node) && node.expression.kind === ts.SyntaxKind.ThisKeyword) {
      const v = this.stateByName.get(node.name.text);
      if (!v) {
        this.diags.error(node, 'JETH065', `unknown state variable 'this.${node.name.text}'`);
        return undefined;
      }
      if (v.type.kind === 'mapping') {
        this.diags.error(
          node,
          'JETH153',
          `mapping 'this.${node.name.text}' cannot be read directly; index it (this.${node.name.text}[key])`,
        );
        return undefined;
      }
      this.currentReadsState = true;
      if (isBytesLike(v.type)) return { kind: 'dynStateRead', type: v.type, slot: v.slot };
      if (v.type.kind === 'array') {
        if (v.type.length !== undefined) {
          // return this.fa (whole fixed array): encoded inline from storage by the
          // recursive encoder (static value / static-struct elements -> flat leaves).
          // A fixed array of a DYNAMIC element (Arr<string,N>/Arr<D,N>) is not a valid
          // state var (rejected at declaration), so this is always a static aggregate.
          return {
            kind: 'arrayValue',
            type: v.type,
            arr: { base: { kind: 'fixedArray', baseSlot: v.slot, length: v.type.length }, elem: v.type.element },
          };
        }
        // a storage array of value / static-struct / DYNAMIC-struct (D[]) / bytes/string
        // (string[]) / nested dynamic-array (u256[][], string[][]) element: encoded by the
        // storage-source recursive encoder on return (unbounded nesting).
        return {
          kind: 'arrayValue',
          type: v.type,
          arr: { base: { kind: 'stateArray', slot: v.slot }, elem: v.type.element },
        };
      }
      if (v.type.kind === 'struct') {
        // a whole struct read from storage (return this.d): a static struct flattens
        // to inline words; a DYNAMIC struct (with a bytes/string/array field) is
        // head/tail encoded by the storage-source recursive encoder on return.
        return { kind: 'structValue', type: v.type, baseSlot: v.slot };
      }
      return { kind: 'stateRead', type: v.type, slot: v.slot, offset: v.offset, varName: v.name };
    }

    // msg.* / block.* / tx.* globals (PropertyAccess on a reserved identifier not
    // shadowed by a local/param/state var; shadowing wins, matching Solidity).
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isIdentifier(node.expression) &&
      GLOBALS[node.expression.text] !== undefined &&
      !this.isVisibleLocal(node.expression.text) &&
      !this.stateByName.has(node.expression.text)
    ) {
      return this.checkGlobal(node);
    }

    // <address>.balance (incl. address(this).balance): the account balance as u256 (env read).
    if (ts.isPropertyAccessExpression(node) && node.name.text === 'balance') {
      const base = this.checkExpr(node.expression);
      if (base && base.type.kind === 'address') {
        if (this.attachedBuiltinCollision(node, node.expression, base.type, 'balance')) return undefined;
        this.currentReadsEnv = true; // forbidden in @pure
        return { kind: 'balance', type: U256, addr: base };
      }
    }

    // <address>.code -> bytes (EXTCODESIZE + EXTCODECOPY); <address>.codehash -> bytes32 (EXTCODEHASH).
    // Both are environment reads (allowed in @view, forbidden in @pure), like .balance.
    if (ts.isPropertyAccessExpression(node) && (node.name.text === 'code' || node.name.text === 'codehash')) {
      const base = this.checkExpr(node.expression);
      if (base && base.type.kind === 'address') {
        if (this.attachedBuiltinCollision(node, node.expression, base.type, node.name.text)) return undefined;
        this.currentReadsEnv = true; // forbidden in @pure
        const member = node.name.text as 'code' | 'codehash';
        return {
          kind: 'extCode',
          type: member === 'code' ? { kind: 'bytes' } : { kind: 'bytesN', size: 32 },
          addr: base,
          member,
        };
      }
    }

    // indexing: array a[i] -> elem, bytes b[i] -> bytes1, or mapping this.m[k]
    if (ts.isElementAccessExpression(node)) {
      // bytesN[i] -> bytes1: a byte extract from a fixed-bytes VALUE (solc allows indexing a fixed
      // bytes value). The result is byte i, left-aligned, with a runtime OOB Panic(0x32) and a
      // compile error on a constant out-of-range index. Probe the base type cheaply (a param/local
      // identifier or this.<state>) so this never double-evaluates an array/mapping base.
      if (node.argumentExpression) {
        let bt: JethType | undefined;
        if (ts.isIdentifier(node.expression)) bt = this.lookupLocal(node.expression.text);
        else if (
          ts.isPropertyAccessExpression(node.expression) &&
          node.expression.expression.kind === ts.SyntaxKind.ThisKeyword
        )
          bt = this.stateByName.get(node.expression.name.text)?.type;
        if (bt && bt.kind === 'bytesN') {
          const base = this.checkExpr(node.expression);
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!base || !index) return undefined;
          if (index.kind === 'literalInt' && (index.value < 0n || index.value >= BigInt(bt.size))) {
            this.diags.error(
              node,
              'JETH152',
              `byte index ${index.value} is out of range for ${displayName(bt)} (valid 0..${bt.size - 1})`,
            );
            return undefined;
          }
          return { kind: 'byteIndex', type: BYTES1, base, index: this.coerce(index, U256, node.argumentExpression) };
        }
        // Indexing a fixed/dynamic-bytes VALUE produced by an expression whose base is NOT a
        // plain identifier or this.<state> (a call like keccak256(b)/bytes32(x)/abi.encodePacked(b),
        // a parenthesized value (x), or a global like msg.sig). solc allows b[i] on any bytesN /
        // bytes value. Resolve the base by its TYPE rather than its syntactic shape. Only claim
        // base shapes that no other element-access handler owns (a call expr, a parenthesized
        // expr, or a non-shadowed global property access) so this never double-evaluates / mis-
        // binds an array/mapping/struct base. lowerByteIndex already supports a bytesN word and a
        // dynamic bytes value.
        if (!bt) {
          const stripped = stripParens(node.expression);
          const isGlobalProp =
            ts.isPropertyAccessExpression(stripped) &&
            ts.isIdentifier(stripped.expression) &&
            GLOBALS[stripped.expression.text] !== undefined &&
            !this.isVisibleLocal(stripped.expression.text) &&
            !this.stateByName.has(stripped.expression.text);
          if (ts.isCallExpression(stripped) || stripped !== node.expression || isGlobalProp) {
            const base = this.checkExpr(node.expression);
            if (!base) return undefined;
            if (base.type.kind === 'bytesN' || base.type.kind === 'bytes') {
              const index = this.checkExpr(node.argumentExpression, U256);
              if (!index) return undefined;
              if (
                base.type.kind === 'bytesN' &&
                index.kind === 'literalInt' &&
                (index.value < 0n || index.value >= BigInt(base.type.size))
              ) {
                this.diags.error(
                  node,
                  'JETH152',
                  `byte index ${index.value} is out of range for ${displayName(base.type)} (valid 0..${base.type.size - 1})`,
                );
                return undefined;
              }
              return {
                kind: 'byteIndex',
                type: BYTES1,
                base,
                index: this.coerce(index, U256, node.argumentExpression),
              };
            }
            if (base.type.kind === 'string') {
              this.diags.error(node, 'JETH205', "'string' is not indexable; only 'bytes' supports b[i]");
              return undefined;
            }
          }
        }
      }
      // A read m[i]...[k] on a nested dynamic array calldata param (T[][], T[][][],
      // string[][], ...): the inner array m[i]...[k-1] is resolved via cdNestedElem
      // (descending the per-level inner-offset tables); the final index then reads
      // either a static VALUE element (arrayGet) or a string/bytes element
      // (cdDynArrayElem). The inner offset tables / bounds are applied at codegen
      // (Panic 0x32 on any dim OOB). Only commit when the base resolves to a
      // cdNestedElem array (a genuine nested-dynamic-array navigation).
      if (
        ts.isElementAccessExpression(node.expression) &&
        node.argumentExpression &&
        this.nestedDynArrayRoot(node.expression)
      ) {
        const innerArr = this.resolveArrayExpr(node.expression);
        if (innerArr && innerArr.base.kind === 'cdNestedElem') {
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!index) return undefined;
          const idx = this.coerce(index, U256, node.argumentExpression);
          if (isBytesLike(innerArr.elem)) {
            return { kind: 'cdDynArrayElem', type: innerArr.elem, arr: innerArr, index: idx };
          }
          if (isStaticValueType(innerArr.elem)) {
            return { kind: 'arrayGet', type: innerArr.elem, arr: innerArr, index: idx };
          }
          // a still-deeper element (the value at m[i][j] is itself a dynamic array,
          // e.g. m[i][j] of a T[][][]) is itself an ArrayExpr; the [k] index that
          // would read INTO it is handled by resolveArrayExpr on the outer node, so
          // this point is only reached when the element is neither value nor bytes-
          // like nor a dynamic array. Such shapes are gated by the type tree.
          return undefined;
        }
      }
      // A read s.grid[i]...[k] on a NESTED-dynamic-array field of a calldata dyn-struct
      // param (T[][], T[][][], string[][]): the inner array s.grid[i]...[k-1] resolves via
      // cdDynFieldNested (descending the per-level inner-offset tables from the field's tail);
      // the final index reads a static VALUE element (arrayGet) or a string/bytes element
      // (cdDynArrayElem). Mirrors the cdNestedElem dispatch above (Panic 0x32 on any dim OOB).
      if (ts.isElementAccessExpression(node.expression) && node.argumentExpression) {
        const innerArr = this.resolveArrayExpr(node.expression);
        if (innerArr && innerArr.base.kind === 'cdDynFieldNested') {
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!index) return undefined;
          const idx = this.coerce(index, U256, node.argumentExpression);
          if (isBytesLike(innerArr.elem))
            return { kind: 'cdDynArrayElem', type: innerArr.elem, arr: innerArr, index: idx };
          if (isStaticValueType(innerArr.elem))
            return { kind: 'arrayGet', type: innerArr.elem, arr: innerArr, index: idx };
          return undefined; // a still-deeper dynamic-array element is handled by the outer resolveArrayExpr
        }
      }
      // a[i][j] where a[i] is the inner array of a MIXED calldata composite (cdSubElem):
      // dynamic-of-fixed (Arr<u256,2>[]) or fixed-of-dynamic (Arr<u256[],N>). [j] reads a value
      // element (or a bytes/string element if the inner is string[]/bytes[]).
      if (ts.isElementAccessExpression(node.expression) && node.argumentExpression) {
        const innerArr = this.resolveArrayExpr(node.expression);
        if (innerArr && innerArr.base.kind === 'cdSubElem') {
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!index) return undefined;
          const idx = this.coerce(index, U256, node.argumentExpression);
          if (isBytesLike(innerArr.elem))
            return { kind: 'cdDynArrayElem', type: innerArr.elem, arr: innerArr, index: idx };
          if (isStaticValueType(innerArr.elem))
            return { kind: 'arrayGet', type: innerArr.elem, arr: innerArr, index: idx };
          return undefined;
        }
      }
      // this.m[k][i] read where this.m[k] is a mapping-valued string[]/bytes[]: the
      // base is not a direct `this.x`, so resolve it via resolveArrayExpr and read
      // the element header at keccak(lenSlot)+i (strArrayElem). Other mapping-valued
      // arrays (value elements) keep their existing arrayGet path via resolveMapAccess.
      if (ts.isElementAccessExpression(node.expression) && node.argumentExpression) {
        const mapArr = this.resolveArrayExpr(node.expression);
        if (
          mapArr &&
          (mapArr.base.kind === 'mapArray' || mapArr.base.kind === 'placeArray') &&
          isBytesLike(mapArr.elem)
        ) {
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!index) return undefined;
          this.currentReadsState = true;
          return {
            kind: 'strArrayElem',
            type: mapArr.elem,
            arr: mapArr,
            index: this.coerce(index, U256, node.argumentExpression),
          };
        }
      }
      // this.m[k][i] where m: mapping<K, bytes>: byte-index the dynamic mapping value
      // (this.m[k] is a bytes value -> mapDynValue). `string` is not indexable. Only
      // probe when node.expression genuinely roots at `this.<state mapping>`, so the
      // resolveMapAccess probe never fires a spurious diagnostic on a local-array index.
      if (ts.isElementAccessExpression(node.expression) && node.argumentExpression) {
        let probe: ts.Expression = node.expression;
        while (ts.isElementAccessExpression(probe)) probe = probe.expression;
        const rootsAtStateMapping =
          ts.isPropertyAccessExpression(probe) &&
          probe.expression.kind === ts.SyntaxKind.ThisKeyword &&
          this.stateByName.get(probe.name.text)?.type.kind === 'mapping';
        if (rootsAtStateMapping) {
          const r = this.resolveMapAccess(node.expression);
          if (!r) return undefined;
          if (isBytesLike(r.valueType)) {
            if (r.valueType.kind === 'string') {
              this.diags.error(node, 'JETH205', "'string' is not indexable; only 'bytes' supports b[i]");
              return undefined;
            }
            const base = this.checkExpr(node.expression);
            const index = this.checkExpr(node.argumentExpression, U256);
            if (!base || !index) return undefined;
            return { kind: 'byteIndex', type: BYTES1, base, index: this.coerce(index, U256, node.argumentExpression) };
          }
        }
      }
      // (c ? xs : ys)[i]: index a memory array produced by an expression (a ternary).
      // The base is not a named local so baseDynType is undefined; resolve via the
      // memArrayExpr path and read the value element.
      if (node.argumentExpression) {
        const ma = this.resolveArrayExpr(node.expression);
        if (ma && ma.base.kind === 'memArrayExpr' && isStaticValueType(ma.elem)) {
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!index) return undefined;
          return { kind: 'arrayGet', type: ma.elem, arr: ma, index: this.coerce(index, U256, node.argumentExpression) };
        }
      }
      // A WHOLE inner dynamic array reached by a multi-step chain used as a value
      // (return this.m[k][i] / this.ddd[i][j] / this.dd[i]): resolveArrayExpr folds it to
      // a placeArray; encode it from storage on return (the element/length/push paths use
      // the same placeArray). Only a node that is itself a dynamic array matches.
      {
        const whole = this.resolveArrayExpr(node);
        if (whole && whole.base.kind === 'placeArray') {
          this.currentReadsState = true;
          return { kind: 'arrayValue', type: { kind: 'array', element: whole.elem }, arr: whole };
        }
      }
      // A whole struct element of a mapping-valued struct array (this.md[k][i]): the
      // base this.md[k] is not a direct this.x so baseDynType is undefined; resolve it
      // via resolveArrayExpr (mapArray). Direct state/fixed struct arrays are handled in
      // the baseDynType block below. Bounds-checked at codegen (Panic 0x32).
      if (node.argumentExpression && ts.isElementAccessExpression(node.expression)) {
        const sa = this.resolveArrayExpr(node.expression);
        if (sa && sa.elem.kind === 'struct' && (sa.base.kind === 'mapArray' || sa.base.kind === 'placeArray')) {
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!index) return undefined;
          this.currentReadsState = true;
          return {
            kind: 'structArrayElem',
            type: sa.elem,
            arr: sa,
            index: this.coerce(index, U256, node.argumentExpression),
          };
        }
      }
      // A string[]/bytes[] element of a STRUCT-FIELD / nested dynamic-element array (this.d.xs[i],
      // this.s.inner.xs[i]): resolveArrayExpr folds the base to a placeArray; the element is a
      // dynamic string/bytes at keccak(lenSlot)+i (strArrayElem). State/fixed/mapping bases are
      // handled elsewhere (baseDynType block / mapArr); this covers the placeArray base only.
      if (node.argumentExpression) {
        const da = this.resolveArrayExpr(node.expression);
        if (da && isBytesLike(da.elem) && da.base.kind === 'placeArray') {
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!index) return undefined;
          this.currentReadsState = true;
          return {
            kind: 'strArrayElem',
            type: da.elem,
            arr: da,
            index: this.coerce(index, U256, node.argumentExpression),
          };
        }
      }
      const bt = this.baseDynType(node.expression);
      if (bt && bt.kind === 'array') {
        const arr = this.resolveArrayExpr(node.expression);
        if (!arr || !node.argumentExpression) return undefined;
        // string[] / bytes[] element a[i] yields the i-th dynamic element (a string/
        // bytes value). A calldata param re-encodes it as a standalone top-level
        // value on return (cdDynArrayElem); a storage / mapping-valued one reads the
        // element header at keccak(lenSlot)+i, a normal storage bytes/string
        // (strArrayElem). Both bounds-check i (Panic 0x32).
        if (isBytesLike(arr.elem)) {
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!index) return undefined;
          const idx = this.coerce(index, U256, node.argumentExpression);
          if (arr.base.kind === 'calldataArray') {
            return { kind: 'cdDynArrayElem', type: arr.elem, arr, index: idx };
          }
          if (arr.base.kind === 'stateArray' || arr.base.kind === 'mapArray' || arr.base.kind === 'fixedArray') {
            this.currentReadsState = true;
            return { kind: 'strArrayElem', type: arr.elem, arr, index: idx };
          }
          this.diags.error(node, 'JETH217', 'this string[]/bytes[] element form is not supported yet');
          return undefined;
        }
        if (arr.elem.kind === 'struct') {
          // A whole storage/fixed/mapping struct element (return this.recs[i]) is encoded
          // from the element slot by the storage-source encoder; calldata struct elements
          // (echo) stay gated. Bounds-checked (Panic 0x32 / const OOB compile error).
          if (arr.base.kind === 'stateArray' || arr.base.kind === 'fixedArray' || arr.base.kind === 'mapArray') {
            const index = this.checkExpr(node.argumentExpression, U256);
            if (!index) return undefined;
            const idx = this.coerce(index, U256, node.argumentExpression);
            if (!this.checkFixedBound(arr, idx, node.argumentExpression)) return undefined;
            this.currentReadsState = true;
            return { kind: 'structArrayElem', type: arr.elem, arr, index: idx };
          }
          // A whole struct element of a CALLDATA struct array (return ps[i]): copy the element's
          // calldata head (contiguous static struct / offset-located dynamic struct) into a fresh
          // ABI return blob via the recursive calldata codec. Bounds-checked at codegen (Panic 0x32).
          if (arr.base.kind === 'calldataArray') {
            const index = this.checkExpr(node.argumentExpression, U256);
            if (!index) return undefined;
            const idx = this.coerce(index, U256, node.argumentExpression);
            return { kind: 'cdStructArrayElem', type: arr.elem, arr, index: idx };
          }
          this.diags.error(
            node,
            'JETH230',
            'reading a whole struct element of a calldata array is not supported yet (access a value field)',
          );
          return undefined;
        }
        if (arr.elem.kind === 'array') {
          // return this.dd[i] (a whole inner array of a storage nested array): the inner
          // array is a placeArray; encode it from storage on return (unbounded nesting).
          const inner = this.resolveArrayExpr(node);
          if (inner && inner.base.kind === 'placeArray') {
            this.currentReadsState = true;
            return { kind: 'arrayValue', type: arr.elem, arr: inner };
          }
          // a whole FIXED inner-array row of a 2D fixed/storage array (return this.g[i]):
          // a static aggregate at the element slot; encoded inline by the storage encoder
          // (structArrayElem computes the slot and routes through returnStorageValue).
          if (
            arr.elem.length !== undefined &&
            (arr.base.kind === 'stateArray' || arr.base.kind === 'fixedArray' || arr.base.kind === 'mapArray')
          ) {
            const index = this.checkExpr(node.argumentExpression, U256);
            if (!index) return undefined;
            const idx = this.coerce(index, U256, node.argumentExpression);
            if (!this.checkFixedBound(arr, idx, node.argumentExpression)) return undefined;
            this.currentReadsState = true;
            return { kind: 'structArrayElem', type: arr.elem, arr, index: idx };
          }
          this.diags.error(
            node,
            'JETH230',
            'reading a whole array-of-array element is a later step (access a value field)',
          );
          return undefined;
        }
        const index = this.checkExpr(node.argumentExpression, U256);
        if (!index) return undefined;
        const idx = this.coerce(index, U256, node.argumentExpression);
        if (!this.checkFixedBound(arr, idx, node.argumentExpression)) return undefined;
        if (arr.base.kind !== 'calldataArray' && arr.base.kind !== 'memArray' && arr.base.kind !== 'memArrayExpr')
          this.currentReadsState = true;
        return { kind: 'arrayGet', type: arr.elem, arr, index: idx };
      }
      if (bt && isBytesLike(bt)) {
        if (bt.kind === 'string') {
          this.diags.error(node, 'JETH205', "'string' is not indexable; only 'bytes' supports b[i]");
          return undefined;
        }
        if (!node.argumentExpression) {
          this.diags.error(node, 'JETH150', 'index expression required');
          return undefined;
        }
        const base = this.checkExpr(node.expression);
        const index = this.checkExpr(node.argumentExpression, U256);
        if (!base || !index) return undefined;
        return { kind: 'byteIndex', type: BYTES1, base, index: this.coerce(index, U256, node.argumentExpression) };
      }
      // d.b[i] where d.b is a bytes field of a DYNAMIC-field struct MEMORY local: the base
      // resolves to a memDynField (bytes); byte-index it (Panic 0x32). Must precede the
      // calldata dynamic-struct resolver below, which would mis-bind the memory local.
      if (
        ts.isPropertyAccessExpression(node.expression) &&
        ts.isIdentifier(node.expression.expression) &&
        this.memDynStructLocals.has(node.expression.expression.text) &&
        node.argumentExpression
      ) {
        const base = this.checkExpr(node.expression);
        if (!base) return undefined;
        if (base.type.kind === 'string') {
          this.diags.error(node, 'JETH205', "'string' is not indexable; only 'bytes' supports b[i]");
          return undefined;
        }
        if (base.type.kind !== 'bytes') {
          this.diags.error(node, 'JETH212', `cannot index ${displayName(base.type)}`);
          return undefined;
        }
        const index = this.checkExpr(node.argumentExpression, U256);
        if (!index) return undefined;
        return { kind: 'byteIndex', type: BYTES1, base, index: this.coerce(index, U256, node.argumentExpression) };
      }
      // this.<chain>.b[j] where the base is a bytes field of a STORAGE dynamic
      // struct (this.e.b[j], this.recs[i].b[j], this.o.inner.b[j]): the base resolves
      // (via the struct-field / resolveAccess read paths) to a bytes value
      // (dynPlaceRead). Byte-index it (Panic 0x32). Only commit when the base is a
      // property/element access that reads a storage dynamic-struct bytes field.
      if (
        (ts.isPropertyAccessExpression(node.expression) || ts.isElementAccessExpression(node.expression)) &&
        node.argumentExpression &&
        this.isStorageDynStructBytesField(node.expression)
      ) {
        const base = this.checkExpr(node.expression);
        if (!base) return undefined;
        if (base.type.kind === 'string') {
          this.diags.error(node, 'JETH205', "'string' is not indexable; only 'bytes' supports b[i]");
          return undefined;
        }
        if (base.type.kind !== 'bytes') {
          this.diags.error(node, 'JETH212', `cannot index ${displayName(base.type)}`);
          return undefined;
        }
        const index = this.checkExpr(node.argumentExpression, U256);
        if (!index) return undefined;
        return { kind: 'byteIndex', type: BYTES1, base, index: this.coerce(index, U256, node.argumentExpression) };
      }
      // d.s[i] where d.s is a bytes field of a dynamic-struct param: byte index.
      // s.xs[i] where s.xs is a dynamic VALUE-array field: array element (calldata).
      if (ts.isPropertyAccessExpression(node.expression)) {
        const dyn = this.resolveCdDynStruct(node.expression);
        if (dyn) {
          if (!dyn.result) return undefined; // committed but errored
          const base = dyn.result;
          if (base.kind === 'arrayValue' && base.type.kind === 'array' && node.argumentExpression) {
            const index = this.checkExpr(node.argumentExpression, U256);
            if (!index) return undefined;
            const idx = this.coerce(index, U256, node.argumentExpression);
            // a string[]/bytes[] field element (s.tags[i]): the per-element offset table
            // resolves the i-th dynamic value, re-encoded as a standalone top-level value.
            if (isBytesLike(base.arr.elem)) {
              return { kind: 'cdDynArrayElem', type: base.arr.elem, arr: base.arr, index: idx };
            }
            // a dynamic-struct array field element used WHOLE (return s.items[i]): copy the
            // i-th element tuple into a fresh ABI return blob (bounds-checked Panic 0x32).
            if (base.arr.elem.kind === 'struct') {
              return { kind: 'cdStructArrayElem', type: base.arr.elem, arr: base.arr, index: idx };
            }
            return { kind: 'arrayGet', type: base.arr.elem, arr: base.arr, index: idx };
          }
          if (base.type.kind === 'string') {
            this.diags.error(node, 'JETH205', "'string' is not indexable; only 'bytes' supports b[i]");
            return undefined;
          }
          if (base.type.kind !== 'bytes' || !node.argumentExpression) {
            this.diags.error(node, 'JETH212', `cannot index ${displayName(base.type)}`);
            return undefined;
          }
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!index) return undefined;
          return { kind: 'byteIndex', type: BYTES1, base, index: this.coerce(index, U256, node.argumentExpression) };
        }
      }
      // this.bb[i][j]: byte-index j into a storage/mapping bytes[] element bb[i].
      // The inner access bb[i] resolves to a strArrayElem (a bytes value); index it.
      if (ts.isElementAccessExpression(node.expression) && node.argumentExpression) {
        const innerArr = this.resolveArrayExpr(node.expression.expression);
        if (
          innerArr &&
          isBytesLike(innerArr.elem) &&
          (innerArr.base.kind === 'stateArray' ||
            innerArr.base.kind === 'mapArray' ||
            innerArr.base.kind === 'calldataArray')
        ) {
          if (innerArr.elem.kind === 'string') {
            this.diags.error(node, 'JETH205', "'string' is not indexable; only 'bytes' supports b[i]");
            return undefined;
          }
          const base = this.checkExpr(node.expression); // -> strArrayElem (bytes)
          const index = this.checkExpr(node.argumentExpression, U256);
          if (!base || !index) return undefined;
          return { kind: 'byteIndex', type: BYTES1, base, index: this.coerce(index, U256, node.argumentExpression) };
        }
      }
      // ps[i].xs[j]: index an array FIELD of a calldata struct-array element. node is the
      // outer [j]; node.expression is ps[i].xs (a field of the i-th struct element).
      //  - STATIC struct element + FIXED value-array field (Arr<u64,2>): the field elements
      //    are inline in the element's head; read the j-th word (cdArrayField + elemIndex).
      //  - DYNAMIC struct element + DYNAMIC value-array field (u64[]): resolveCdDynArrayField
      //    gives the array via the tuple tail offset; index it as an ordinary calldata array.
      if (
        ts.isPropertyAccessExpression(node.expression) &&
        ts.isElementAccessExpression(node.expression.expression) &&
        node.argumentExpression
      ) {
        const fieldNode = node.expression;
        const elemAccess = node.expression.expression;
        const bt = this.baseDynType(elemAccess.expression);
        if (bt && bt.kind === 'array' && bt.element.kind === 'struct') {
          const struct = bt.element;
          if (isDynamicType(struct)) {
            // dynamic-struct array element: ps[i].xs resolves to a value-array; index it.
            const arrBase = this.resolveCdDynArrayField(fieldNode, struct);
            if (arrBase && arrBase.kind === 'arrayValue' && arrBase.type.kind === 'array') {
              const index = this.checkExpr(node.argumentExpression, U256);
              if (!index) return undefined;
              return {
                kind: 'arrayGet',
                type: arrBase.arr.elem,
                arr: arrBase.arr,
                index: this.coerce(index, U256, node.argumentExpression),
              };
            }
            return undefined; // resolveCdDynArrayField already emitted any diagnostic
          }
          // static struct element: the field must be a FIXED value-array (inline head).
          const fidx = struct.fields.findIndex((f) => f.name === fieldNode.name.text);
          if (fidx >= 0) {
            const f = struct.fields[fidx]!;
            if (f.type.kind === 'array' && f.type.length !== undefined && isStaticValueType(f.type.element)) {
              const arr = this.resolveArrayExpr(elemAccess.expression);
              if (arr && arr.base.kind === 'calldataArray') {
                const eidxE = this.checkExpr(elemAccess.argumentExpression!, U256);
                if (!eidxE) return undefined;
                const eidx = this.coerce(eidxE, U256, elemAccess.argumentExpression!);
                const jE = this.checkExpr(node.argumentExpression, U256);
                if (!jE) return undefined;
                const jIdx = this.coerce(jE, U256, node.argumentExpression);
                if (jIdx.kind === 'literalInt' && (jIdx.value < 0n || jIdx.value >= BigInt(f.type.length))) {
                  this.diags.error(
                    node.argumentExpression,
                    'JETH211',
                    `array index ${jIdx.value} out of bounds for length ${f.type.length}`,
                  );
                  return undefined;
                }
                const headWords = struct.fields.slice(0, fidx).reduce((n, ff) => n + abiHeadWords(ff.type), 0);
                return {
                  kind: 'cdArrayField',
                  type: f.type.element,
                  arr,
                  index: eidx,
                  headWords,
                  fieldType: f.type.element,
                  elemIndex: jIdx,
                  elemLength: f.type.length,
                };
              }
            }
          }
        }
      }
      const r = this.resolveMapAccess(node);
      if (!r) return undefined;
      if (r.valueType.kind === 'mapping') {
        this.diags.error(node, 'JETH153', 'a mapping value cannot be read directly; index it fully');
        return undefined;
      }
      // A whole struct/array mapping value (`return this.m[k]`) is encoded from the
      // mapping slot by the storage-source recursive encoder (mapGet loads one word,
      // so it only fits value types). Reading fields/elements (this.m[k].field,
      // this.m[k][i]) is handled separately.
      if (r.valueType.kind === 'struct' || r.valueType.kind === 'array') {
        this.currentReadsState = true;
        return { kind: 'mapStorageValue', type: r.valueType, baseSlot: r.baseSlot, keys: r.keys, keyTypes: r.keyTypes };
      }
      // A bytes/string mapping value is a dynamic value living at the mapping slot
      // (short inline / long at keccak(slot)); it flows through the dynamic-value
      // machinery (encode-to-memory for return, .length, byte-index, overwrite-store).
      if (isBytesLike(r.valueType)) {
        this.currentReadsState = true;
        return { kind: 'mapDynValue', type: r.valueType, baseSlot: r.baseSlot, keys: r.keys, keyTypes: r.keyTypes };
      }
      this.currentReadsState = true;
      return { kind: 'mapGet', type: r.valueType, baseSlot: r.baseSlot, keys: r.keys, keyTypes: r.keyTypes };
    }

    // address(this) / address(0n) / payable(x) / uint160(x) / bytes20(x) casts
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      !this.isVisibleLocal(node.expression.text) &&
      !this.stateByName.has(node.expression.text)
    ) {
      const callee = node.expression.text;
      if (callee === 'address') return this.checkAddressCall(node);
      // global builtins (solc reserved): gasleft() / keccak256(bytes|string) / blockhash(uint).
      if (callee === 'gasleft') {
        if (node.arguments.length !== 0) this.diags.error(node, 'JETH170', 'gasleft() takes no arguments');
        this.currentReadsEnv = true; // forbidden in @pure
        return { kind: 'global', type: U256, op: 'gas' };
      }
      if (callee === 'keccak256') {
        if (node.arguments.length !== 1) {
          this.diags.error(node, 'JETH170', 'keccak256(...) takes exactly one argument');
          return undefined;
        }
        const arg = this.checkExpr(node.arguments[0]!, this.bytesLiteralExpected(node.arguments[0]!));
        if (!arg) return undefined;
        // solc: keccak256 takes a single `bytes` (a string/bytesN does NOT implicitly convert).
        if (arg.type.kind !== 'bytes') {
          this.diags.error(
            node,
            'JETH171',
            `keccak256(...) requires a bytes argument, got ${displayName(arg.type)} (use abi.encodePacked(...) / bytes(...) for a string)`,
          );
          return undefined;
        }
        return { kind: 'keccak', type: { kind: 'bytesN', size: 32 }, arg };
      }
      if (callee === 'sha256' || callee === 'ripemd160') {
        if (node.arguments.length !== 1) {
          this.diags.error(node, 'JETH170', `${callee}(...) takes exactly one argument`);
          return undefined;
        }
        const arg = this.checkExpr(node.arguments[0]!, this.bytesLiteralExpected(node.arguments[0]!));
        if (!arg) return undefined;
        if (arg.type.kind !== 'bytes') {
          this.diags.error(
            node,
            'JETH171',
            `${callee}(...) requires a bytes argument, got ${displayName(arg.type)} (use abi.encodePacked(...) / bytes(...) for a string)`,
          );
          return undefined;
        }
        const isSha = callee === 'sha256';
        return {
          kind: 'precompileHash',
          type: { kind: 'bytesN', size: isSha ? 32 : 20 },
          arg,
          addr: isSha ? 2 : 3,
          leftShift: isSha ? 0 : 96,
        };
      }
      if (callee === 'ecrecover') {
        // RAW unsafe builtin (= solc ecrecover, the 0x01 precompile). ecrecover(hash, v, r, s) -> address:
        // address(0) on ANY failure, NEVER reverts, NO malleability/v/zero checks. byte-identical to solc.
        if (node.arguments.length !== 4) {
          this.diags.error(node, 'JETH170', 'ecrecover(...) takes exactly four arguments (hash, v, r, s)');
          return undefined;
        }
        const BYTES32: JethType = { kind: 'bytesN', size: 32 };
        const U8: JethType = { kind: 'uint', bits: 8 };
        const hash = this.checkExpr(node.arguments[0]!, BYTES32);
        const v = this.checkExpr(node.arguments[1]!, U8);
        const r = this.checkExpr(node.arguments[2]!, BYTES32);
        const s = this.checkExpr(node.arguments[3]!, BYTES32);
        if (!hash || !v || !r || !s) return undefined;
        for (const [x, ty, i] of [
          [hash, BYTES32, 0],
          [r, BYTES32, 2],
          [s, BYTES32, 3],
        ] as const) {
          if (x.type.kind !== 'bytesN' || x.type.size !== 32) {
            this.diags.error(
              node.arguments[i]!,
              'JETH171',
              `ecrecover(...) requires a bytes32 ${['hash', '', 'r', 's'][i]}, got ${displayName(x.type)}`,
            );
            return undefined;
          }
        }
        if (!isInteger(v.type)) {
          this.diags.error(
            node.arguments[1]!,
            'JETH171',
            `ecrecover(...) v must be an integer, got ${displayName(v.type)}`,
          );
          return undefined;
        }
        return {
          kind: 'ecrecover',
          type: ADDRESS,
          hash,
          v: this.coerce(v, U8, node.arguments[1]!),
          r,
          s,
        };
      }
      if (callee === 'recover') {
        // SAFE OZ-5.x ECDSA.recover. Two overloads by arity: recover(hash, sig:bytes) (65-byte check) and
        // recover(hash, v, r, s) (split form, no length check). Both reject high-s (s>HALF, STRICT) and a
        // zero recovered signer with the exact OZ custom-error selectors. byte-identical to OZ ECDSA.
        const BYTES32: JethType = { kind: 'bytesN', size: 32 };
        const U8: JethType = { kind: 'uint', bits: 8 };
        if (node.arguments.length === 2) {
          const hash = this.checkExpr(node.arguments[0]!, BYTES32);
          const sig = this.checkExpr(node.arguments[1]!, this.bytesLiteralExpected(node.arguments[1]!));
          if (!hash || !sig) return undefined;
          if (hash.type.kind !== 'bytesN' || hash.type.size !== 32) {
            this.diags.error(
              node.arguments[0]!,
              'JETH171',
              `recover(...) requires a bytes32 hash, got ${displayName(hash.type)}`,
            );
            return undefined;
          }
          if (sig.type.kind !== 'bytes') {
            this.diags.error(
              node.arguments[1]!,
              'JETH171',
              `recover(...) requires a bytes signature, got ${displayName(sig.type)} (use bytes(...) for a string)`,
            );
            return undefined;
          }
          return { kind: 'recover', type: ADDRESS, hash, sig };
        }
        if (node.arguments.length === 4) {
          const hash = this.checkExpr(node.arguments[0]!, BYTES32);
          const v = this.checkExpr(node.arguments[1]!, U8);
          const r = this.checkExpr(node.arguments[2]!, BYTES32);
          const s = this.checkExpr(node.arguments[3]!, BYTES32);
          if (!hash || !v || !r || !s) return undefined;
          for (const [x, i] of [
            [hash, 0],
            [r, 2],
            [s, 3],
          ] as const) {
            if (x.type.kind !== 'bytesN' || x.type.size !== 32) {
              this.diags.error(
                node.arguments[i]!,
                'JETH171',
                `recover(...) requires a bytes32 ${['hash', '', 'r', 's'][i]}, got ${displayName(x.type)}`,
              );
              return undefined;
            }
          }
          if (!isInteger(v.type)) {
            this.diags.error(
              node.arguments[1]!,
              'JETH171',
              `recover(...) v must be an integer, got ${displayName(v.type)}`,
            );
            return undefined;
          }
          return { kind: 'recover', type: ADDRESS, hash, v: this.coerce(v, U8, node.arguments[1]!), r, s };
        }
        this.diags.error(node, 'JETH170', 'recover(...) takes (hash, sig) or (hash, v, r, s)');
        return undefined;
      }
      if (callee === 'tryRecover') {
        // destructure-only (like addr.tryCall): `let [ok, signer] = tryRecover(hash, sig)`. A scalar use
        // reaches here only as a misuse; the destructure path is handled by resolveTryRecover.
        this.diags.error(
          node,
          'JETH066',
          'tryRecover returns a tuple; destructure it as `let [ok, signer] = tryRecover(hash, sig)`',
        );
        return undefined;
      }
      if (callee === 'modexp') {
        // modexp(base, exp, mod): arbitrary-precision modular exponentiation (precompile 0x05) -> bytes
        // of length mod.length. mod=0 is a VALID input (returns mod.length zero bytes) - NO zero gate.
        if (node.arguments.length !== 3) {
          this.diags.error(node, 'JETH170', 'modexp(...) takes exactly three arguments (base, exp, mod)');
          return undefined;
        }
        const base = this.checkExpr(node.arguments[0]!, this.bytesLiteralExpected(node.arguments[0]!));
        const exp = this.checkExpr(node.arguments[1]!, this.bytesLiteralExpected(node.arguments[1]!));
        const mod = this.checkExpr(node.arguments[2]!, this.bytesLiteralExpected(node.arguments[2]!));
        if (!base || !exp || !mod) return undefined;
        for (const [x, i] of [
          [base, 0],
          [exp, 1],
          [mod, 2],
        ] as const) {
          if (x.type.kind !== 'bytes') {
            this.diags.error(
              node.arguments[i]!,
              'JETH171',
              `modexp(...) requires a bytes argument, got ${displayName(x.type)} (use abi.encodePacked(...) / bytes(...) for an integer)`,
            );
            return undefined;
          }
        }
        return { kind: 'modexp', type: BYTES, base, exp, mod };
      }
      if (callee === 'bn256Add' || callee === 'bn256Mul' || callee === 'bn256Pairing') {
        return this.checkBn256Call(node, callee);
      }
      if (callee === 'blake2f') {
        return this.checkBlake2fCall(node);
      }
      if (callee === 'pointEvaluation') {
        // destructure-only: `let [fe, modulus] = pointEvaluation(...)`. A scalar use is a misuse; the
        // env-read flag is set on every path (incl. this rejection) so the @pure check stays consistent.
        this.currentReadsEnv = true;
        this.diags.error(
          node,
          'JETH066',
          'pointEvaluation yields two values; destructure it as `const [fe, modulus] = pointEvaluation(versionedHash, z, y, commitment, proof)`',
        );
        return undefined;
      }
      if (callee === 'addmod' || callee === 'mulmod') {
        // addmod(a,b,m) = (a+b) % m, mulmod(a,b,m) = (a*b) % m, both full-precision (no overflow);
        // m==0 yields 0 (the EVM ADDMOD/MULMOD opcode, no revert). solc args are uint256.
        if (node.arguments.length !== 3) {
          this.diags.error(node, 'JETH170', `${callee}(...) takes exactly three arguments`);
          return undefined;
        }
        const a = this.checkExpr(node.arguments[0]!, U256);
        const b = this.checkExpr(node.arguments[1]!, U256);
        const m = this.checkExpr(node.arguments[2]!, U256);
        if (!a || !b || !m) return undefined;
        for (const [x, i] of [
          [a, 0],
          [b, 1],
          [m, 2],
        ] as const) {
          if (!isInteger(x.type)) {
            this.diags.error(
              node.arguments[i]!,
              'JETH171',
              `${callee}(...) requires integer arguments, got ${displayName(x.type)}`,
            );
            return undefined;
          }
        }
        // solc rejects a compile-time-constant zero modulus ("Arithmetic modulo zero"). A constant
        // arithmetic modulus is already folded to a literalInt by checkExpr, so this catches `0n` and
        // folded forms like `1n - 1n` alike. (A runtime-zero modulus still reverts Panic(0x12).)
        if (m.kind === 'literalInt' && m.value === 0n) {
          this.diags.error(
            node.arguments[2]!,
            'JETH172',
            `${callee}(...) modulus is a compile-time zero (arithmetic modulo zero)`,
          );
          return undefined;
        }
        return {
          kind: 'modOp',
          type: U256,
          op: callee,
          a: this.coerce(a, U256, node.arguments[0]!),
          b: this.coerce(b, U256, node.arguments[1]!),
          m: this.coerce(m, U256, node.arguments[2]!),
        };
      }
      if (callee === 'blockhash') {
        if (node.arguments.length !== 1) {
          this.diags.error(node, 'JETH170', 'blockhash(...) takes exactly one argument');
          return undefined;
        }
        const arg = this.checkExpr(node.arguments[0]!, U256);
        if (!arg) return undefined;
        if (!isInteger(arg.type)) {
          this.diags.error(
            node,
            'JETH171',
            `blockhash(...) requires an integer argument, got ${displayName(arg.type)}`,
          );
          return undefined;
        }
        this.currentReadsEnv = true; // forbidden in @pure
        return {
          kind: 'blockhash',
          type: { kind: 'bytesN', size: 32 },
          arg: this.coerce(arg, U256, node.arguments[0]!),
        };
      }
      if (callee === 'blobhash') {
        // EIP-4844 (cancun): blobhash(index) -> the versioned hash of the index-th blob, or 0 (out of range).
        if (node.arguments.length !== 1) {
          this.diags.error(node, 'JETH170', 'blobhash(...) takes exactly one argument');
          return undefined;
        }
        const arg = this.checkExpr(node.arguments[0]!, U256);
        if (!arg) return undefined;
        if (!isInteger(arg.type)) {
          this.diags.error(node, 'JETH171', `blobhash(...) requires an integer argument, got ${displayName(arg.type)}`);
          return undefined;
        }
        this.currentReadsEnv = true; // forbidden in @pure
        return {
          kind: 'blobhash',
          type: { kind: 'bytesN', size: 32 },
          arg: this.coerce(arg, U256, node.arguments[0]!),
        };
      }
      // --- Phase 1 proxies: EIP-1167 minimal-proxy builtins (OZ Clones 5.1) ---
      if (
        callee === 'isContract' ||
        callee === 'clone' ||
        callee === 'cloneDeterministic' ||
        callee === 'cloneWithArgs' ||
        callee === 'cloneDeterministicWithArgs' ||
        callee === 'predictClone' ||
        callee === 'predictCloneWithArgs' ||
        callee === 'cloneArgs'
      ) {
        return this.checkCloneBuiltin(node, callee);
      }
      // --- Phase 2a proxies: EIP-1967 upgradeable-proxy foundation builtins ---
      if (
        callee === 'proxyInit' ||
        callee === 'upgradeProxy' ||
        callee === 'proxyImplementation' ||
        callee === 'proxyAdmin' ||
        callee === 'proxyInitBeacon' ||
        callee === 'proxyBeacon'
      ) {
        return this.checkProxyBuiltin(node, callee);
      }
      // --- Phase 3 DIAMOND: synthesis-only builtins (only valid inside a synthesized @diamond). ---
      if (
        callee === 'diamondInit' ||
        callee === '__diamondDelegateInit' ||
        callee === '__diamondFacets' ||
        callee === '__diamondCutPacked' ||
        callee === '__diamondFacetsPacked' ||
        callee === '__diamondFacetSelectorsPacked' ||
        callee === '__diamondFacetAddressesPacked' ||
        callee === 'diamondInitSolidstate' ||
        callee === '__diamondCutSolidstate' ||
        callee === '__revertSelector'
      ) {
        return this.checkDiamondBuiltin(node, callee);
      }
      // `Color(x)` is an integer -> enum range-checked conversion; an enum is a branded uint8, so
      // isBrandedAlias already routes it, but name it explicitly for clarity.
      if (
        callee === 'payable' ||
        resolvePrimitiveName(callee) ||
        this.isEnumName(callee) ||
        this.isBrandedAlias(callee)
      )
        return this.checkCast(node, callee);
      const st = this.structsByName.get(callee);
      if (st && st.kind === 'struct') return this.checkStructConstruct(node, st);
      // Phase 6: a bare interface wrapper `IFoo(addr)` used as a VALUE (no .method() applied). An
      // interface-tagged address is not usable on its own; it must be followed by a method call.
      if (this.interfacesByName.has(callee) && !this.isVisibleLocal(callee)) {
        this.diags.error(
          node,
          'JETH358',
          `'${callee}(addr)' is an interface handle and cannot be used as a value; call a method on it, e.g. ${callee}(addr).someMethod(...)`,
        );
        return undefined;
      }
      // an internal/private/public contract function called by name -> internal call.
      if (this.funcsByName.has(callee)) return this.checkInternalCall(node, callee, false);
      // F6: a generic internal call `f<T>(x)` / `f(x)` in value position.
      if (this.genericsByName.has(callee)) return this.checkGenericCall(node, callee, false);
    }

    // `super.method(args)` in value position -> resolve up the linearization (inheritance).
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.expression.kind === ts.SyntaxKind.SuperKeyword
    ) {
      return this.checkSuperCall(node, node.expression.name.text, false);
    }
    // `this.method(args)` (TS-idiomatic internal call) -> internal-call semantics.
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.expression.kind === ts.SyntaxKind.ThisKeyword &&
      this.funcsByName.has(node.expression.name.text)
    ) {
      return this.checkInternalCall(node, node.expression.name.text, false);
    }
    // F6: `this.f<T>(args)` generic internal call in value position.
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.expression.kind === ts.SyntaxKind.ThisKeyword &&
      this.genericsByName.has(node.expression.name.text)
    ) {
      return this.checkGenericCall(node, node.expression.name.text, false);
    }

    // Phase A: qualified library call `L.f(args)` in value position. `L` is a known @library name
    // (and not shadowed by a local/state value), `f` is one of its functions -> an internal call to
    // the library function (byte-identical to a contract internal call). Placed before the built-in
    // method resolvers (`L` is a library, never a value receiver, so there is no overlap).
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      this.isLibraryName(node.expression.expression.text) &&
      !this.isVisibleLocal(node.expression.expression.text) &&
      !this.stateByName.has(node.expression.expression.text)
    ) {
      return this.resolveQualifiedLibraryCall(node, node.expression.expression.text, node.expression.name.text, false);
    }

    // abi.encode(...) / abi.encodePacked(...) / abi.encodeWithSelector(sel, ...) /
    // abi.encodeWithSignature(sig, ...) -> a bytes value.
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === 'abi' &&
      !this.isVisibleLocal('abi') &&
      !this.stateByName.has('abi') &&
      ['encode', 'encodePacked', 'encodeWithSelector', 'encodeWithSignature'].includes(node.expression.name.text)
    ) {
      return this.checkAbiEncode(node, node.expression.name.text);
    }

    // abi.decode(data, T) / abi.decode(data, [T1, ...]) -> the decoded typed value (single form) or a
    // tuple (only valid in a destructuring; rejected with a clear message in value position).
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === 'abi' &&
      !this.isVisibleLocal('abi') &&
      !this.stateByName.has('abi') &&
      node.expression.name.text === 'decode'
    ) {
      return this.checkAbiDecode(node);
    }

    // `<bytes>.decode(T)` method sugar: exact sugar for abi.decode(<bytes>, T). Only treated as a
    // decode when the receiver is a bytes value and the single type argument resolves to a type; the
    // tuple form `<bytes>.decode([...])` is a destructuring source (handled in checkTupleDecl).
    if (ts.isCallExpression(node)) {
      const dm = this.abiDecodeMethod(node);
      if (dm && !ts.isArrayLiteralExpression(dm.typeArg) && this.isBytesValueExpr(dm.data)) {
        const r = this.resolveAbiDecode(node, dm.data, dm.typeArg);
        if (!r) return undefined;
        return { kind: 'abiDecode', type: r.types[0]!, data: r.data };
      }
    }

    // Phase 6: `<calldata bytes>.slice(start [, end])` -> a zero-copy calldata bytes slice, byte-identical
    // to solc's data[start:end]. Only fires when the receiver is a CALLDATA bytes value (peek-rollback so a
    // non-bytes `.slice` receiver falls through to the interface-call / other handlers below).
    if (ts.isCallExpression(node)) {
      const sl = this.resolveCalldataSlice(node);
      if (sl === 'reject') return undefined;
      if (sl) return sl;
    }

    // Phase 6: `<string|bytes>.concat(...)` and static `string.concat(...)` / `bytes.concat(...)` -> a
    // tightly-packed concatenation, byte-identical to solc string.concat / bytes.concat.
    if (ts.isCallExpression(node)) {
      const cc = this.resolveConcat(node);
      if (cc === 'reject') return undefined;
      if (cc) return cc;
    }

    // Phase 6: high-level typed interface call `IFoo(addr [, { value?, gas? }]).method(args)` in value
    // position. A single-value method yields the abi.decode of the returndata; a void method cannot be
    // a value (must be a statement); a tuple method must be destructured (handled in checkTupleDecl).
    {
      const ic = this.resolveInterfaceCall(node);
      if (ic === 'handled') return undefined;
      if (ic) {
        if (ic.returnTypes) {
          this.diags.error(
            node,
            'JETH356',
            `this interface method returns a tuple; bind it with a destructuring \`let [a, b] = IFoo(addr).${(node as ts.CallExpression & { expression: ts.PropertyAccessExpression }).expression.name.text}(...)\``,
          );
          return undefined;
        }
        if (ic.returnType.kind === 'void') {
          this.diags.error(
            node,
            'JETH357',
            'this interface method returns void and cannot be used as a value (call it as a statement)',
          );
          return undefined;
        }
        return { kind: 'abiDecode', type: ic.returnType, data: ic.call };
      }
    }

    // Phase 6: external low-level calls `<addr>.call/staticcall({ data, value?, gas?, success })`
    // -> bytes (returndata). `tryCall`/`tryStaticcall` return [bool, bytes] and are only valid in a
    // tuple destructuring (handled in checkTupleDecl); used in value position they error here.
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      EXT_CALL_METHODS.has(node.expression.name.text)
    ) {
      return this.checkExternalCall(node, node.expression.name.text);
    }

    // Phase A: an attached library method `x.f(args)` == `L.f(x, ...args)`. Placed AFTER every
    // built-in method resolver (interface call / .decode / .slice / .concat / external call), so a
    // built-in method of the same name on x's type ALWAYS wins (matches solc). Only fires when x's
    // type has a (T, f) attachment from a @using(L) decorator AND the args fit; otherwise it returns
    // 'no-match' and falls through to the normal member-access error.
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      this.libraryAttachments.size > 0 &&
      !(node.expression.expression.kind === ts.SyntaxKind.ThisKeyword) &&
      !(node.expression.expression.kind === ts.SyntaxKind.SuperKeyword)
    ) {
      const recvType = this.trialExprType(node.expression.expression);
      if (recvType) {
        const r = this.resolveAttachedLibraryCall(
          node,
          node.expression.expression,
          recvType,
          node.expression.name.text,
          false,
        );
        if (r !== 'no-match') return r;
      }
    }

    // object literal { ...base, x: v } / { x: 1n, y: 2n } -> struct construction when the
    // expected type is a known struct; otherwise point at positional construction.
    if (ts.isObjectLiteralExpression(node)) {
      if (expected && expected.kind === 'struct') return this.checkStructLiteral(node, expected);
      this.diags.error(
        node,
        'JETH227',
        'object-literal struct construction needs a known struct type from context (annotate the target), or use positional StructName(...)',
      );
      return undefined;
    }

    // local / param read
    if (ts.isIdentifier(node)) {
      const t = this.lookupLocal(node.text);
      if (!t) {
        this.diags.error(node, 'JETH072', `unknown identifier '${node.text}'`);
        return undefined;
      }
      if (isBytesLike(t))
        return this.memDynLocals.has(node.text)
          ? { kind: 'dynLocalRead', type: t, name: node.text }
          : { kind: 'dynParamRead', type: t, name: node.text };
      // a whole MEMORY-aggregate (struct) local (return p / let q = p / arg p): the register
      // holds a pointer to the ABI-unpacked image. G9.
      if (this.memAggregateLocals.has(node.text)) {
        return { kind: 'memAggregate', type: t, local: node.text };
      }
      // a whole DYNAMIC-field struct memory local (return d): re-encode head/tail from the
      // pointer-headed image via the dynamic-struct tuple encoder (memory TupleSrc).
      if (this.memDynStructLocals.has(node.text)) {
        return { kind: 'memDynStructValue', type: t, local: node.text };
      }
      // a MEMORY array local (return xs): the register holds a pointer to [len][elems];
      // ABI-encoded from memory on return.
      if (t.kind === 'array' && this.memArrayLocals.has(node.text)) {
        return {
          kind: 'arrayValue',
          type: t,
          arr: { base: { kind: 'memArray', varName: node.text }, elem: t.element },
        };
      }
      // a whole dynamic-array param echo, OR a fixed array of a DYNAMIC element
      // (Arr<dyn,N>) echo: re-encoded head/tail via the recursive codec.
      if (t.kind === 'array' && (t.length === undefined || isDynamicType(t.element))) {
        return {
          kind: 'arrayValue',
          type: t,
          arr: { base: { kind: 'calldataArray', name: node.text }, elem: t.element },
        };
      }
      // a whole DYNAMIC-struct param echo (return d): re-encoded head/tail (4e-6).
      if (t.kind === 'struct' && isDynamicType(t)) {
        return { kind: 'cdDynStructValue', type: t, param: node.text };
      }
      // a whole STATIC struct / fixed-array param echo (return a): re-encoded inline via
      // the recursive calldata codec (the dynamic shapes were handled above).
      if ((t.kind === 'array' || t.kind === 'struct') && isStaticType(t)) {
        return { kind: 'cdAggregateValue', type: t, param: node.text };
      }
      if (t.kind === 'array' || t.kind === 'struct') {
        this.diags.error(
          node,
          'JETH230',
          `passing or returning a whole ${displayName(t)} calldata parameter is not supported yet (access its fields/elements)`,
        );
        return undefined;
      }
      return { kind: 'localRead', type: t, name: node.text };
    }

    // x++ / x-- / ++x / --x in VALUE position (let p = x++, a[x++], f(x++)): postfix
    // yields the old value, prefix the new. (The statement form is desugared earlier.)
    if (ts.isPostfixUnaryExpression(node)) {
      return this.checkIncDecExpr(node.operand, node.operator === ts.SyntaxKind.PlusPlusToken, false, node);
    }
    if (
      ts.isPrefixUnaryExpression(node) &&
      (node.operator === ts.SyntaxKind.PlusPlusToken || node.operator === ts.SyntaxKind.MinusMinusToken)
    ) {
      return this.checkIncDecExpr(node.operand, node.operator === ts.SyntaxKind.PlusPlusToken, true, node);
    }

    // unary
    if (ts.isPrefixUnaryExpression(node)) {
      return this.checkUnary(node, expected);
    }

    // binary
    if (ts.isBinaryExpression(node)) {
      const op = this.binaryToBinOp(node.operatorToken.kind);
      if (!op) {
        this.diags.error(node.operatorToken, 'JETH073', `unsupported binary operator`);
        return undefined;
      }
      // Constant folding (solc parity): a fully-constant arithmetic expression is evaluated as an
      // exact rational and collapsed to a single range-checked integer literal. This fixes the eager
      // integer-truncation miscompile (`(10n/4n)*4n` == 10, not 8) and rejects compile-time overflow /
      // div-by-zero / non-integer constants the way solc does. Non-constant operands fall through to
      // runtime codegen below (so variable arithmetic, incl. `unchecked` wrapping, is unchanged).
      // An address-like hex literal (a 40-digit checksummed literal, or an invalid 39/41-digit /
      // bad-checksum one) must NOT be const-folded as an integer: solc rejects arithmetic on an
      // address (and rejects a bad-checksum literal outright). Fall through to checkExpr/buildBinary,
      // which types the operand as `address` (-> JETH082) or emits the checksum error (-> JETH049).
      const addrLike =
        this.classifyAddressHexLiteral(node.left) !== 'plain' || this.classifyAddressHexLiteral(node.right) !== 'plain';
      if (!addrLike && ['+', '-', '*', '/', '%', '**', '<<', '>>', '&', '|', '^'].includes(op)) {
        const folded = this.foldConstRational(node);
        if (folded !== undefined) {
          if ('err' in folded) {
            this.diags.error(node, 'JETH079', folded.err);
            return undefined;
          }
          return this.literalFromConst(folded, node, expected);
        }
      }
      const left = this.checkExpr(node.left, expected);
      if (!left) return undefined;
      // the exponent of `**` and the amount of a shift are independent (unsigned) values, not
      // unified with the left operand (so `bytes4 x << 4n` treats 4n as a uint, not a bytes4).
      // For `**` and shifts the right operand is an independent unsigned value; for COMPARISONS the
      // operands take their NATURAL types and unify afterward (so an out-of-range literal is not
      // force-rejected here but widened to a common type by widenLiteralOperand, matching solc).
      // A LITERAL right operand takes its own mobile type (not forced into left.type) when there is no
      // outer expected, so `varN OP bigLit` widens to the common type instead of range-failing the
      // literal against the (narrower) variable type - matching solc (e.g. `u8 a + 1000` computes at u16).
      const rightLit = this.asIntLiteral(node.right) !== undefined;
      const rightExpected =
        op === '**' || op === '<<' || op === '>>' || this.isComparison(op)
          ? undefined
          : rightLit
            ? expected
            : (expected ?? left.type);
      const right = this.checkExpr(node.right, rightExpected);
      if (!right) return undefined;
      return this.buildBinary(op, left, right, node);
    }

    this.diags.error(node, 'JETH074', `unsupported expression: ${ts.SyntaxKind[node.kind]}`);
    return undefined;
  }

  private checkUnary(node: ts.PrefixUnaryExpression, expected?: JethType): Expr | undefined {
    const operand = this.checkExpr(node.operand, expected);
    if (!operand) return undefined;
    switch (node.operator) {
      case ts.SyntaxKind.MinusToken:
        if (operand.type.kind !== 'int') {
          this.diags.error(node, 'JETH075', `unary '-' requires a signed integer, got ${displayName(operand.type)}`);
          return undefined;
        }
        return { kind: 'unary', type: operand.type, op: '-', operand, unchecked: this.currentUnchecked };
      case ts.SyntaxKind.ExclamationToken:
        if (operand.type.kind !== 'bool') {
          this.diags.error(node, 'JETH076', `unary '!' requires bool, got ${displayName(operand.type)}`);
          return undefined;
        }
        return { kind: 'unary', type: BOOL, op: '!', operand, unchecked: false };
      case ts.SyntaxKind.TildeToken:
        // ~ is a bit-vector complement: solc allows it on integers AND fixed bytes (bytesN).
        if (!isInteger(operand.type) && operand.type.kind !== 'bytesN') {
          this.diags.error(
            node,
            'JETH077',
            `unary '~' requires an integer or bytesN, got ${displayName(operand.type)}`,
          );
          return undefined;
        }
        return { kind: 'unary', type: operand.type, op: '~', operand, unchecked: false };
      default:
        this.diags.error(node, 'JETH078', `unsupported unary operator`);
        return undefined;
    }
  }

  private buildBinary(op: BinOp, left: Expr, right: Expr, node: ts.Node): Expr | undefined {
    // Logical &&/|| -> bool
    if (op === '&&' || op === '||') {
      if (left.type.kind !== 'bool' || right.type.kind !== 'bool') {
        this.diags.error(node, 'JETH080', `'${op}' requires bool operands`);
        return undefined;
      }
      return { kind: 'binary', type: BOOL, op, left, right, unchecked: false };
    }

    // Comparisons -> bool. Allowed on enums (compares the underlying uint8); two DIFFERENT enums
    // are rejected by the brand-mismatch path inside unifyOperands.
    if (this.isComparison(op)) {
      // solc allows comparing an integer variable to an out-of-range literal by widening BOTH to the
      // smallest common type of the same signedness that holds the literal (a legal, usually-
      // degenerate comparison: e.g. `uint8 == 256` -> compare in uint16). Try that before the normal
      // unify (which would emit a range error). A signedness mismatch (e.g. `int8 == 200`, whose
      // literal's mobile type is unsigned, or `uint8 == -1`) is left to unify, which rejects it.
      const unified = this.widenLiteralOperand(left, right) ?? this.unifyOperands(left, right, node);
      if (!unified) return undefined;
      // == / != / ordered comparisons are valid ONLY on value types. solc rejects them on structs,
      // arrays (fixed/dynamic), bytes/string and mappings ("Built-in binary operator == cannot be
      // applied to types ..."), so we must too (closing a soundness over-acceptance: JETH emitted
      // runtime bytecode for an aggregate comparison that solc never compiles at all).
      if (!isStaticValueType(unified[0].type)) {
        this.diags.error(
          node,
          'JETH088',
          `operator '${op}' cannot be applied to ${displayName(unified[0].type)} operands (comparisons are only valid on value types: uintN/intN/bool/address/bytesN/enum)`,
        );
        return undefined;
      }
      // ORDERED comparisons (< > <= >=) need an ordered type. solc allows them on int/uint,
      // address, bytesN, and enums, but REJECTS them on bool (only == / != are valid on bool):
      // "Built-in binary operator > cannot be applied to types bool and bool."
      if (op !== '==' && op !== '!=' && unified[0].type.kind === 'bool') {
        this.diags.error(
          node,
          'JETH082',
          `operator '${op}' cannot be applied to bool operands (only == and != are valid on bool)`,
        );
        return undefined;
      }
      return { kind: 'binary', type: BOOL, op, left: unified[0], right: unified[1], unchecked: false };
    }

    // Arithmetic / bitwise / shift / ** on an enum operand is a type error (solc forbids it):
    // an enum is not an arithmetic type. Only comparisons (handled above) are allowed; cast to an
    // integer first to do math. (Comparisons already returned; everything below is arithmetic-ish.)
    if (isEnum(left.type) || isEnum(right.type)) {
      const en = isEnum(left.type) ? left.type : right.type;
      this.diags.error(
        node,
        'JETH279',
        `arithmetic on enum '${displayName(en)}' is not allowed; cast to an integer first (e.g. u8(x))`,
      );
      return undefined;
    }

    // Shifts: the value may be an integer OR a bytesN (bit-vector shift, like solc); the result
    // type follows the left operand. The amount must be an UNSIGNED integer - solc rejects a signed
    // shift amount ("the type of the shift amount ... must be unsigned").
    if (op === '<<' || op === '>>') {
      if (!isInteger(left.type) && left.type.kind !== 'bytesN') {
        this.diags.error(
          node,
          'JETH081',
          `shift requires an integer or bytesN left operand, got ${displayName(left.type)}`,
        );
        return undefined;
      }
      if (right.type.kind !== 'uint') {
        this.diags.error(node, 'JETH081', `shift amount must be an unsigned integer, got ${displayName(right.type)}`);
        return undefined;
      }
      return { kind: 'binary', type: left.type, op, left, right, unchecked: this.currentUnchecked };
    }

    // Exponentiation: result type follows the base (left); the exponent is a separate
    // non-negative integer (not unified with the base). Checked (Panic 0x11 on overflow).
    if (op === '**') {
      if (!isInteger(left.type)) {
        this.diags.error(node, 'JETH082', `'**' requires an integer base, got ${displayName(left.type)}`);
        return undefined;
      }
      if (!isInteger(right.type)) {
        this.diags.error(node, 'JETH082', `'**' requires an integer exponent, got ${displayName(right.type)}`);
        return undefined;
      }
      // solc rejects a SIGNED exponent ("Exponentiation power is not allowed to be a signed type").
      if (right.type.kind === 'int') {
        this.diags.error(
          node,
          'JETH082',
          `'**' exponent cannot be a signed integer (solc requires an unsigned power), got ${displayName(right.type)}`,
        );
        return undefined;
      }
      return { kind: 'binary', type: left.type, op, left, right, unchecked: this.currentUnchecked };
    }

    // Bitwise & | ^ : operands may be integer OR bytesN (bit-vector ops, like solc). Arithmetic
    // + - * / % : integer operands only.
    const unified = this.unifyOperands(left, right, node);
    if (!unified) return undefined;
    const isBitwise = op === '&' || op === '|' || op === '^';
    const ok = isBitwise ? isInteger(unified[0].type) || unified[0].type.kind === 'bytesN' : isInteger(unified[0].type);
    if (!ok) {
      this.diags.error(
        node,
        'JETH082',
        `operator '${op}' requires ${isBitwise ? 'integer or bytesN' : 'integer'} operands, got ${displayName(unified[0].type)}`,
      );
      return undefined;
    }
    return {
      kind: 'binary',
      type: unified[0].type,
      op,
      left: unified[0],
      right: unified[1],
      unchecked: this.currentUnchecked,
    };
  }

  /** Make two operands share a type, retyping a literal toward the other side. */
  private unifyOperands(left: Expr, right: Expr, node: ts.Node): [Expr, Expr] | undefined {
    if (typesEqual(left.type, right.type)) return [left, right];
    // address and address payable share the same EVM word; compare freely. But a branded
    // address is nominally distinct: only fold when both sides carry the same brand (or none).
    if (left.type.kind === 'address' && right.type.kind === 'address' && left.type.brand === right.type.brand)
      return [left, right];
    // A literal operand that overflows the OTHER operand's type but fits a WIDER same-signedness type:
    // widen BOTH to that common type (solc: `uint8 a + 1000` computes in uint16, overflow at uint16).
    // Returns null when the literal fits (falls through to retype, staying at the operand type) or on a
    // signedness mismatch (left to the retype path, which rejects it).
    const widened = this.widenLiteralOperand(left, right);
    if (widened) return widened;
    const lLit = left.kind === 'literalInt';
    const rLit = right.kind === 'literalInt';
    if (rLit && !lLit) {
      const r = this.retypeLiteral(right, left.type, node);
      return r ? [left, r] : undefined;
    }
    if (lLit && !rLit) {
      const l = this.retypeLiteral(left, right.type, node);
      return l ? [l, right] : undefined;
    }
    // mixed-width same-signedness operands (u8 + u256, i16 < i256, bytes4 == bytes32):
    // widen the narrower to the wider common type (Solidity-identical), no runtime op.
    const common = commonNumericType(left.type, right.type);
    if (common) {
      const l = isImplicitWiden(left.type, common)
        ? ({ kind: 'cast', type: common, from: left.type, operand: left } as Expr)
        : left;
      const r = isImplicitWiden(right.type, common)
        ? ({ kind: 'cast', type: common, from: right.type, operand: right } as Expr)
        : right;
      return [l, r];
    }
    this.diags.error(
      node,
      'JETH083',
      `type mismatch: ${displayName(left.type)} vs ${displayName(right.type)} (no implicit conversion)`,
    );
    return undefined;
  }

  private retypeLiteral(lit: Expr, target: JethType, node: ts.Node, allowEnumToInt = false): Expr | undefined {
    if (lit.kind !== 'literalInt') return undefined;
    // An address-typed literal (a 40-hex-digit checksummed literal, or address(x)) behaves like an
    // address VALUE: it converts only to uint160 (explicit cast) and never implicitly to any integer
    // (solc: `uint256 x = 0x<addr>` and `uint8(0x<addr>)` are both errors). Same-type (address) is
    // handled by typesEqual upstream; bytesN targets fall through to isCastAllowed (address<->bytes20).
    if (lit.type.kind === 'address') {
      if (allowEnumToInt && target.kind === 'uint' && target.bits === 160 && this.inRange(lit.value, target)) {
        return { ...lit, type: target };
      }
      return undefined;
    }
    // An enum-typed literal (Color.Member or Color(x)) is nominally an enum: it implicitly converts
    // ONLY to the same enum, and that case is caught upstream by typesEqual so it never reaches here.
    // Arriving here with an enum literal therefore means an implicit enum -> int (or enum -> a
    // different enum) conversion, which solc forbids (`uint256 x = Color.Blue;` is an error); an
    // explicit cast is required. The explicit-cast call site passes allowEnumToInt. This mirrors the
    // non-literal enum value, which also rejects with JETH085 via isImplicitWiden's brand check.
    if (isEnum(lit.type)) {
      if (!allowEnumToInt) {
        this.diags.error(
          node,
          'JETH085',
          `cannot implicitly convert enum '${displayName(lit.type)}' to ${displayName(target)} (no implicit enum conversion; use an explicit cast)`,
        );
        return undefined;
      }
      // an EXPLICIT enum -> integer cast: solc allows ONLY enum -> uintN (any width), never enum -> intN
      // (int8(Color.Blue) is rejected; go through uintN first). Mirrors isCastAllowed for runtime values.
      if (target.kind === 'int') {
        this.diags.error(
          node,
          'JETH170',
          `explicit conversion not allowed from enum '${displayName(lit.type)}' to ${displayName(target)} (an enum converts only to an unsigned integer)`,
        );
        return undefined;
      }
    }
    // A bare integer literal cannot become an enum without an explicit conversion (solc rejects
    // `Color c = 1;`). An already-enum-typed literal (Color.Member / Color(x)) reaches coerce via
    // typesEqual and never lands here, so any literal arriving with an enum target is a bare int.
    if (isEnum(target) && !isEnum(lit.type)) {
      this.diags.error(
        node,
        'JETH280',
        `cannot use a bare integer literal as enum '${displayName(target)}'; use ${displayName(target)}(${lit.value}) or ${displayName(target)}.<Member>`,
      );
      return undefined;
    }
    if (!isInteger(target)) {
      if (target.kind === 'bytesN') {
        // the literal 0 always converts (all-zero left-aligned word).
        if (lit.value === 0n) return { ...lit, type: target };
        // a HEX literal whose source byte width == N converts (left-aligned in the high N bytes); a
        // decimal literal or a wrong-width hex literal needs an explicit bytesN(...) cast.
        if (lit.hexBytes === target.size)
          return { kind: 'literalInt', type: target, value: lit.value << BigInt((32 - target.size) * 8) };
      }
      this.diags.error(node, 'JETH084', `cannot use integer literal as ${displayName(target)}`);
      return undefined;
    }
    if (!this.inRange(lit.value, target)) {
      this.diags.error(node, 'JETH070', `literal ${lit.value} out of range for ${displayName(target)}`);
      return undefined;
    }
    return { ...lit, type: target };
  }

  /** Coerce an expression to a target type (literal retyping or exact match). */
  private coerce(expr: Expr, target: JethType, node: ts.Node): Expr {
    if (typesEqual(expr.type, target)) return expr;
    if (expr.kind === 'literalInt') {
      const r = this.retypeLiteral(expr, target, node);
      if (r) return r;
      // An ordinary int literal that fails to retype already had its diagnostic emitted by
      // retypeLiteral (out-of-range / bytesN / enum); an ADDRESS-typed literal (a 40-hex-digit
      // checksummed literal) declines silently, so let it fall through to the generic
      // no-implicit-conversion error below (solc rejects `uint256 x = 0x<addr>`).
      if (expr.type.kind !== 'address') return expr;
    }
    // address payable -> address is implicit (same word); the reverse needs payable(). A branded
    // address is nominally distinct, so only this fast-path when the brands match (else fall
    // through to the generic no-implicit-conversion error, matching every other branded base).
    if (expr.type.kind === 'address' && target.kind === 'address' && expr.type.brand === target.brand) {
      if (expr.type.payable || !target.payable) return expr;
      this.diags.error(node, 'JETH172', 'cannot implicitly convert address to address payable (use payable(...))');
      return expr;
    }
    // Implicit WIDENING (Solidity-identical): uintN->uintM, intN->intM (M>=N), bytesN->
    // bytesM (M>=N). Same signedness only; uint<->int / narrowing need an explicit cast.
    if (isImplicitWiden(expr.type, target)) {
      return { kind: 'cast', type: target, from: expr.type, operand: expr };
    }
    this.diags.error(
      node,
      'JETH085',
      `cannot assign ${displayName(expr.type)} to ${displayName(target)} (no implicit conversion; widening must keep the same signedness, narrowing needs an explicit cast)`,
    );
    return expr;
  }

  // ---- constant folding (state initializers) -------------------------------

  private foldConstant(node: ts.Expression, expected: JethType): bigint | boolean | undefined {
    if (ts.isParenthesizedExpression(node)) return this.foldConstant(node.expression, expected);
    if (this.rejectUppercaseHexPrefix(node)) return undefined; // 0X prefix (solc parser error)
    if (this.rejectBadUnderscores(node)) return undefined; // bad underscore placement (solc parser error)
    // constant ternary `c ? a : b` (any target type): fold the constant condition, then the chosen arm.
    if (ts.isConditionalExpression(node)) {
      const c = this.foldConstBool(node.condition);
      if (c !== undefined) {
        const chosen = this.foldConstant(c ? node.whenTrue : node.whenFalse, expected);
        // solc type-checks BOTH arms of a constant conditional. Fold the DEAD arm too: its own errors
        // (out-of-range JETH070, etc.) are emitted, and if it is not a valid constant of the expected
        // type (e.g. div/mod by zero, which folds to undefined) the whole conditional is rejected
        // (the caller emits JETH048), matching solc which rejects a compile-time error in either arm.
        const dead = this.foldConstant(c ? node.whenFalse : node.whenTrue, expected);
        if (dead === undefined) return undefined;
        return chosen;
      }
    }
    // bool constant: a literal, another bool @constant, !/&&/|| or a comparison of constants.
    if (expected.kind === 'bool') {
      const b = this.foldConstBool(node);
      if (b !== undefined) return b;
      const lit = this.asIntLiteral(node);
      if (lit !== undefined) this.diags.error(node, 'JETH086', `cannot assign an integer literal to bool`);
      return undefined;
    }
    if (node.kind === ts.SyntaxKind.TrueKeyword || node.kind === ts.SyntaxKind.FalseKeyword) {
      this.diags.error(node, 'JETH087', `cannot assign a bool literal to ${displayName(expected)}`);
      return undefined;
    }
    // An address-like hex literal where a NON-address constant is expected: a valid 40-digit literal
    // is address-typed (not implicitly convertible), and a 39/41-digit or bad-checksum literal is a
    // hard error. Checked before the integer/bytesN folders (which would otherwise read its value).
    const addrClass = this.classifyAddressHexLiteral(node);
    if (addrClass !== 'plain' && expected.kind !== 'address') {
      if (addrClass === 'address')
        this.diags.error(node, 'JETH086', `cannot assign an address literal to ${displayName(expected)}`);
      else this.diags.error(node, addrClass.code, addrClass.msg);
      return undefined;
    }
    // A constant INTEGER expression: solc folds + - * ** << >> & | ^ % (and exact /) and unary -
    // with UNBOUNDED precision, then range-checks only the FINAL value against the target type.
    if (isInteger(expected)) {
      // TYPE-AWARE typed-constant fold (solc parity): when the expression contains a TYPED operand (a
      // cast uN(x)/iN(x), type(T).max/min, or a typed @constant reference), evaluate it with that
      // operand's TYPE semantics rather than as an unbounded int_const. <<,>> truncate to the LHS width;
      // &,|,^ stay in the common type; +,-,*,**,/,% are checked against the result type (a typed
      // overflow / div-by-0 is a RUNTIME Panic in solc, which a slot-free folded @constant cannot
      // reproduce -> a clean COMPILE rejection here, a safe over-rejection that kills the miscompile);
      // ~ masks to the operand width. The RESULT TYPE must be implicitly convertible (same signedness,
      // not wider) to `expected`. A PURE int_const expression is left to the unbounded path below.
      if (this.containsTypedConstOperand(node)) {
        const tc = this.evalTypedConst(node);
        if (tc === undefined || 'err' in tc || 'revert' in tc) {
          this.diags.error(
            node,
            'JETH070',
            `${'err' in (tc ?? {}) ? (tc as { err: string }).err : 'constant'} is not a valid constant ${displayName(expected)}`,
          );
          return tc !== undefined && 'revert' in tc ? ((tc as { revert: true } & { value?: bigint }).value ?? 0n) : 0n;
        }
        if (tc.type !== 'const') {
          // a TYPED result is implicitly convertible to `expected` iff same signedness and not wider.
          const tb = (tc.type as { brand?: string }).brand;
          const eb = (expected as { brand?: string }).brand;
          if (
            tc.type.kind !== expected.kind ||
            (tc.type as { bits: number }).bits > (expected as { bits: number }).bits ||
            tb !== eb
          ) {
            this.diags.error(
              node,
              'JETH070',
              `type ${displayName(tc.type)} is not implicitly convertible to ${displayName(expected)}`,
            );
            return tc.value;
          }
          return tc.value;
        }
        // an int_const result produced via a typed sub-operand (e.g. 1 << uint8(2)): range-check it.
        if (!this.inRange(tc.value, expected))
          this.diags.error(node, 'JETH070', `constant ${tc.value} out of range for ${displayName(expected)}`);
        return tc.value;
      }
      // `~x` on an UNTYPED integer constant yields the signed int_const -x-1 (solc), folded by
      // evalConstInt with the rest of the expression and range-checked below: a negative result
      // (e.g. `~1` = -2, `~uint(0)` is a typed operand JETH does not fold) is rejected for an
      // unsigned target exactly as solc rejects `uint K = ~1`. No type-width masking here.
      const v = this.evalConstInt(node);
      if (v !== undefined) {
        if (!this.inRange(v, expected))
          this.diags.error(node, 'JETH070', `constant ${v} out of range for ${displayName(expected)}`);
        return v;
      }
      // Fall back to exact-RATIONAL folding for a constant with a FRACTIONAL intermediate that
      // evalConstInt rejects but solc accepts: `(10/4)*4 == 10` (division is exact mid-expression,
      // never truncated). evalConstInt already covered constant refs + type(T).max above. Only a valid
      // INTEGER result is returned (range-checked); a non-integer final value or a rejected expression
      // (div/mod by zero, negative shift) falls through to the caller's single JETH048, as before.
      const r = this.foldConstRational(node);
      if (r !== undefined && !('err' in r) && r.den === 1n) {
        if (!this.inRange(r.num, expected))
          this.diags.error(node, 'JETH070', `constant ${r.num} out of range for ${displayName(expected)}`);
        return r.num;
      }
      return undefined; // not a constant integer expression -> caller emits JETH048
    }
    // address constant: a bare 40-hex-digit checksummed literal (= 0x...) or `address(<int literal>)`.
    if (expected.kind === 'address') {
      if (addrClass === 'address') return this.asIntLiteral(node)!;
      if (addrClass !== 'plain') {
        this.diags.error(node, addrClass.code, addrClass.msg);
        return undefined;
      }
      if (
        ts.isCallExpression(node) &&
        ts.isIdentifier(node.expression) &&
        node.expression.text === 'address' &&
        node.arguments.length === 1
      ) {
        const argClass = this.classifyAddressHexLiteral(node.arguments[0]!);
        if (argClass !== 'plain' && argClass !== 'address') {
          this.diags.error(node, argClass.code, argClass.msg);
          return undefined;
        }
        const a = this.asIntLiteral(node.arguments[0]!);
        if (a !== undefined) {
          if (a < 0n || a >= 1n << 160n) {
            this.diags.error(node, 'JETH070', `literal ${a} out of range for address`);
            return undefined;
          }
          return a;
        }
      }
      return undefined; // not a constant address literal -> caller emits JETH048
    }
    // keccak256(<constant string/bytes>) in a bytes32 @constant -> the hash, folded at compile time
    // (the common typehash / domain-separator-component pattern). The 32-byte hash is the bytes32 word.
    if (
      expected.kind === 'bytesN' &&
      expected.size === 32 &&
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === 'keccak256' &&
      node.arguments.length === 1
    ) {
      const bytes = this.constByteString(node.arguments[0]!);
      if (bytes) return BigInt('0x' + toHex(keccak(bytes)));
    }
    // bytesN constant: `bytesN(<int literal>)` -> the value LEFT-aligned in the high N bytes (the
    // bytesN register form), matching solc's bytesN literal. The bare literal 0 also folds to zero.
    if (expected.kind === 'bytesN') {
      // `~bytesN_const`: complement the value within the high N bytes (the bytesN register form),
      // leaving the low (32-N) bytes zero. solc: ~bytes1(0)=0xff..(byte 0), ~bytes4(0x12345678)=0xedcba987.
      if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.TildeToken) {
        const v = this.foldConstant(node.operand, expected);
        if (typeof v !== 'bigint') return undefined;
        const highMask = ((1n << BigInt(expected.size * 8)) - 1n) << BigInt((32 - expected.size) * 8);
        return ~v & highMask;
      }
      if (
        ts.isCallExpression(node) &&
        ts.isIdentifier(node.expression) &&
        node.expression.text === `bytes${expected.size}` &&
        node.arguments.length === 1
      ) {
        const argClass = this.classifyAddressHexLiteral(node.arguments[0]!);
        if (argClass !== 'plain' && argClass !== 'address') {
          this.diags.error(node, argClass.code, argClass.msg);
          return undefined;
        }
        const a = this.asIntLiteral(node.arguments[0]!);
        if (a !== undefined) {
          // solc rule (mirrors the implicit bare-hex path below and convertCall): converts ONLY for the
          // literal 0 (any spelling) or a HEX literal whose source byte width == size.
          if (a !== 0n && this.hexLiteralBytes(node.arguments[0]!) !== expected.size) {
            this.diags.error(
              node,
              'JETH170',
              `explicit conversion not allowed from integer literal ${a} to bytes${expected.size}`,
            );
            return undefined;
          }
          return a << BigInt((32 - expected.size) * 8); // left-align into the high N bytes
        }
      }
      // a bare HEX literal whose source byte width == N converts implicitly (left-aligned), matching solc.
      if (this.hexLiteralBytes(node) === expected.size) {
        return this.asIntLiteral(node)! << BigInt((32 - expected.size) * 8);
      }
      if (this.asIntLiteral(node) === 0n) return 0n;
      return undefined; // not a constant bytesN literal -> caller emits JETH048
    }
    // non-integer target: any other integer literal/expression is an error.
    const lit = this.asIntLiteral(node);
    if (lit !== undefined) {
      this.diags.error(node, 'JETH086', `cannot assign an integer literal to ${displayName(expected)}`);
      return undefined;
    }
    return undefined;
  }

  /** Evaluate a constant INTEGER expression with UNBOUNDED precision (no intermediate range check),
   *  matching solc's constant folding. Returns the bigint value, or undefined if the expression is
   *  not a foldable integer constant (a non-constant operand, an unsupported op, or - matching solc -
   *  a fractional `/`, a `>>`/`<<`/`**` by a negative amount, or a `/`/`%` by zero). */
  /** Fold a node that denotes a compile-time BOOL: a literal, another bool @constant (bare or this.K),
   *  `!x`, `a && b`/`a || b`, or a comparison of constant integers/bools. Returns the value or undefined. */
  private foldConstBool(node: ts.Expression): boolean | undefined {
    if (ts.isParenthesizedExpression(node)) return this.foldConstBool(node.expression);
    if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
    if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
    const constBool = (n: ts.Expression): boolean | undefined => {
      const name =
        ts.isIdentifier(n) && !this.lookupLocal(n.text)
          ? n.text
          : ts.isPropertyAccessExpression(n) && n.expression.kind === ts.SyntaxKind.ThisKeyword
            ? n.name.text
            : undefined;
      if (name === undefined) return undefined;
      const c = this.constantsByName.get(name);
      return c && typeof c.value === 'boolean' ? c.value : undefined;
    };
    const cb = constBool(node);
    if (cb !== undefined) return cb;
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.ExclamationToken) {
      const x = this.foldConstBool(node.operand);
      return x === undefined ? undefined : !x;
    }
    if (ts.isBinaryExpression(node)) {
      const op = this.binaryToBinOp(node.operatorToken.kind);
      if (op === '&&' || op === '||') {
        const a = this.foldConstBool(node.left),
          b = this.foldConstBool(node.right);
        return a === undefined || b === undefined ? undefined : op === '&&' ? a && b : a || b;
      }
      if (op === '==' || op === '!=' || op === '<' || op === '>' || op === '<=' || op === '>=') {
        // bool==bool or int-comparison of constants
        const ba = this.foldConstBool(node.left),
          bb = this.foldConstBool(node.right);
        let a: bigint | undefined, b: bigint | undefined;
        if (ba !== undefined && bb !== undefined) {
          a = ba ? 1n : 0n;
          b = bb ? 1n : 0n;
        } else {
          // type-aware operand fold: if either side references a TYPED operand (cast/type(T).max/typed
          // @constant), evaluate it with solc type semantics. A typed overflow / div-by-0 inside an
          // operand is a runtime revert in solc, so the whole bool @constant is rejected here (a safe
          // over-rejection). A pure int_const operand keeps the unbounded evalConstInt fold.
          const fold = (n: ts.Expression): bigint | undefined => {
            if (!this.containsTypedConstOperand(n)) return this.evalConstInt(n);
            const r = this.evalTypedConst(n);
            return r === undefined || 'err' in r || 'revert' in r ? undefined : r.value;
          };
          a = fold(node.left);
          b = fold(node.right);
        }
        if (a === undefined || b === undefined) return undefined;
        switch (op) {
          case '==':
            return a === b;
          case '!=':
            return a !== b;
          case '<':
            return a < b;
          case '>':
            return a > b;
          case '<=':
            return a <= b;
          case '>=':
            return a >= b;
        }
      }
    }
    return undefined;
  }

  /** Evaluate a node to a constant byte string (for compile-time keccak256 in a @constant): a string/
   *  template literal (its UTF-8 bytes), `bytes(<that>)`, or `abi.encodePacked(<such literals>)`. */
  private constByteString(node: ts.Expression): Uint8Array | undefined {
    if (ts.isParenthesizedExpression(node)) return this.constByteString(node.expression);
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node))
      return new TextEncoder().encode(node.text);
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === 'bytes' &&
      node.arguments.length === 1
    ) {
      return this.constByteString(node.arguments[0]!);
    }
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === 'abi' &&
      node.expression.name.text === 'encodePacked'
    ) {
      const parts: Uint8Array[] = [];
      for (const a of node.arguments) {
        const b = this.constByteString(a);
        if (!b) return undefined; // a non-string-literal packed arg: not foldable here
        parts.push(b);
      }
      const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
      let o = 0;
      for (const p of parts) {
        out.set(p, o);
        o += p.length;
      }
      return out;
    }
    return undefined;
  }

  /** Fold a node that denotes a compile-time INTEGER: a reference to another integer @constant (a bare
   *  name not shadowed by a local, or `this.K`), or `type(T).max/.min`. Returns the value or undefined. */
  private constIntRef(node: ts.Expression): bigint | undefined {
    if (ts.isIdentifier(node) && !this.lookupLocal(node.text)) {
      const c = this.constantsByName.get(node.text);
      if (c && typeof c.value === 'bigint' && isInteger(c.type)) return c.value;
    }
    if (ts.isPropertyAccessExpression(node) && node.expression.kind === ts.SyntaxKind.ThisKeyword) {
      const c = this.constantsByName.get(node.name.text);
      if (c && typeof c.value === 'bigint' && isInteger(c.type)) return c.value;
    }
    if (
      ts.isPropertyAccessExpression(node) &&
      (node.name.text === 'max' || node.name.text === 'min') &&
      ts.isCallExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === 'type' &&
      node.expression.arguments.length === 1 &&
      ts.isIdentifier(node.expression.arguments[0]!)
    ) {
      const t = resolvePrimitiveName((node.expression.arguments[0] as ts.Identifier).text);
      if (!t || !isInteger(t)) return undefined;
      const isMax = node.name.text === 'max';
      const bits = (t as { bits: number }).bits;
      return t.kind === 'uint'
        ? isMax
          ? (1n << BigInt(bits)) - 1n
          : 0n
        : isMax
          ? (1n << BigInt(bits - 1)) - 1n
          : -(1n << BigInt(bits - 1));
    }
    return undefined;
  }

  /** The CONCRETE type (uintN/intN) of a node that denotes a TYPED constant operand (a typed @constant
   *  reference - a bare name not shadowed by a local, or this.K), or undefined. type(T).max/min and a
   *  cast uN(x)/iN(x) are recognized directly in evalTypedConst/containsTypedConstOperand; this helper
   *  only resolves a constant REFERENCE so the bare-name vs shadowing-local rule matches constIntRef. */
  private constTypedRefType(node: ts.Expression): JethType | undefined {
    let nm: string | undefined;
    if (ts.isIdentifier(node) && !this.lookupLocal(node.text)) nm = node.text;
    else if (ts.isPropertyAccessExpression(node) && node.expression.kind === ts.SyntaxKind.ThisKeyword)
      nm = node.name.text;
    if (nm === undefined) return undefined;
    const c = this.constantsByName.get(nm);
    return c && typeof c.value === 'bigint' && isInteger(c.type) ? c.type : undefined;
  }

  /** True iff `node` (recursively, modulo parentheses) contains a TYPED constant operand: a cast
   *  uN(x)/iN(x), `type(T).max`/`.min`, or a reference to a typed @constant. When true, the @constant
   *  folder evaluates the expression with solc TYPE semantics (evalTypedConst) instead of as an
   *  unbounded int_const. A PURE int_const expression (no typed operand) returns false and is left to
   *  the existing unbounded evalConstInt / rational path, preserving e.g. (10/4)*4 == 10 and 2**200. */
  private containsTypedConstOperand(node: ts.Expression): boolean {
    if (ts.isParenthesizedExpression(node)) return this.containsTypedConstOperand(node.expression);
    if (this.isEnumConstNode(node)) return true;
    if (
      ts.isPropertyAccessExpression(node) &&
      (node.name.text === 'max' || node.name.text === 'min') &&
      ts.isCallExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === 'type'
    )
      return true;
    if (this.constTypedRefType(node) !== undefined) return true;
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && resolvePrimitiveName(node.expression.text)) {
      const ct = resolvePrimitiveName(node.expression.text)!;
      if (isInteger(ct)) return true;
    }
    if (ts.isPrefixUnaryExpression(node)) return this.containsTypedConstOperand(node.operand);
    if (ts.isBinaryExpression(node))
      return this.containsTypedConstOperand(node.left) || this.containsTypedConstOperand(node.right);
    return false;
  }

  /** Reduce `value` into the two's-complement domain of integer type `t` (wrap for uint, sign-extend for
   *  int). Used for solc's typed-constant truncation: <<,>>,&,|,^ and a cast of a TYPED value all keep
   *  the result in the operand/LHS width. */
  private wrapToType(value: bigint, t: { kind: 'uint' | 'int'; bits: number }): bigint {
    const bits = BigInt(t.bits);
    const mod = 1n << bits;
    let r = ((value % mod) + mod) % mod;
    if (t.kind === 'int' && r >= 1n << (bits - 1n)) r -= mod;
    return r;
  }

  /** Common (mobile) result type for an arithmetic/bitwise op (NOT shift) over two typed-const operands,
   *  matching solc: int_const op int_const -> 'const'; a typed operand with an int_const literal promotes
   *  to the smallest type of the typed operand's signedness holding BOTH (a negative literal with an
   *  unsigned typed operand, or a literal that cannot fit, is illegal -> null); two typed operands must
   *  share signedness (else null) and the wider one wins. null means solc rejects the op (sign mismatch). */
  private commonConstType(
    a: { value: bigint; type: JethType | 'const' },
    b: { value: bigint; type: JethType | 'const' },
  ): JethType | 'const' | null {
    if (a.type === 'const' && b.type === 'const') return 'const';
    const promote = (lit: bigint, t: { kind: 'uint' | 'int'; bits: number }): JethType | null => {
      if (lit < 0n) {
        if (t.kind !== 'int') return null;
        for (let m = t.bits; m <= 256; m += 8) {
          const tt = { kind: 'int' as const, bits: m };
          if (this.inRange(lit, tt)) return tt;
        }
        return null;
      }
      if (t.kind === 'uint') {
        for (let m = t.bits; m <= 256; m += 8) {
          const tt = { kind: 'uint' as const, bits: m };
          if (this.inRange(lit, tt)) return tt;
        }
        return null;
      }
      for (let m = t.bits; m <= 256; m += 8) {
        const tt = { kind: 'int' as const, bits: m };
        if (this.inRange(lit, tt)) return tt;
      }
      return null;
    };
    if (a.type === 'const') return promote(a.value, b.type as { kind: 'uint' | 'int'; bits: number });
    if (b.type === 'const') return promote(b.value, a.type as { kind: 'uint' | 'int'; bits: number });
    const at = a.type as { kind: 'uint' | 'int'; bits: number };
    const bt = b.type as { kind: 'uint' | 'int'; bits: number };
    if (at.kind !== bt.kind) return null;
    return at.bits >= bt.bits ? at : bt;
  }

  private isEnumConstNode(node: ts.Expression): boolean {
    if (ts.isParenthesizedExpression(node)) return this.isEnumConstNode(node.expression);
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isIdentifier(node.expression) &&
      this.isEnumName(node.expression.text)
    )
      return true;
    if (
      ts.isPropertyAccessExpression(node) &&
      (node.name.text === 'max' || node.name.text === 'min') &&
      ts.isCallExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === 'type' &&
      node.expression.arguments.length === 1 &&
      ts.isIdentifier(node.expression.arguments[0]!) &&
      this.isEnumName((node.expression.arguments[0] as ts.Identifier).text)
    )
      return true;
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      this.isEnumName(node.expression.text) &&
      node.arguments.length === 1
    )
      return true;
    return false;
  }

  private evalEnumConst(node: ts.Expression): { value: bigint; type: JethType } | { err: string } | undefined {
    if (ts.isParenthesizedExpression(node)) return this.evalEnumConst(node.expression);
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isIdentifier(node.expression) &&
      this.isEnumName(node.expression.text)
    ) {
      const et = this.structsByName.get(node.expression.text)! as JethType & { kind: 'uint'; enumMembers: string[] };
      const idx = et.enumMembers.indexOf(node.name.text);
      if (idx < 0) return { err: `enum '${node.expression.text}' has no member '${node.name.text}'` };
      return { value: BigInt(idx), type: et };
    }
    if (
      ts.isPropertyAccessExpression(node) &&
      (node.name.text === 'max' || node.name.text === 'min') &&
      ts.isCallExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === 'type' &&
      node.expression.arguments.length === 1 &&
      ts.isIdentifier(node.expression.arguments[0]!) &&
      this.isEnumName((node.expression.arguments[0] as ts.Identifier).text)
    ) {
      const et = this.structsByName.get((node.expression.arguments[0] as ts.Identifier).text)! as JethType & {
        kind: 'uint';
        enumMembers: string[];
      };
      return { value: node.name.text === 'max' ? BigInt(et.enumMembers.length - 1) : 0n, type: et };
    }
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      this.isEnumName(node.expression.text) &&
      node.arguments.length === 1
    ) {
      const et = this.structsByName.get(node.expression.text)! as JethType & { kind: 'uint'; enumMembers: string[] };
      const inner = this.evalTypedConst(node.arguments[0]!);
      if (inner === undefined || 'revert' in inner) return undefined; // a runtime-reverting inner is not a foldable enum const
      if ('err' in inner) return inner;
      if (inner.type !== 'const')
        return { err: `enum conversion ${node.expression.text}(...) requires a constant integer` };
      if (inner.value < 0n || inner.value >= BigInt(et.enumMembers.length))
        return {
          err: `value ${inner.value} is out of range for enum '${node.expression.text}' (0..${et.enumMembers.length - 1})`,
        };
      return { value: inner.value, type: et };
    }
    return undefined;
  }

  /** Type-aware constant folder matching solc, used ONLY when containsTypedConstOperand(node) is true.
   *  Returns { value, type } where type is 'const' (int_const) or a concrete uintN/intN; { err } when
   *  solc rejects at COMPILE time (cast of an out-of-range int_const, sign mismatch, unary - on an
   *  unsigned, negative shift/exponent); { revert: true } when solc emits RUNTIME code that reverts
   *  Panic(0x11/0x12) (typed +,-,*,**,unary- overflow, or /,% by zero) - a slot-free folded @constant
   *  cannot reproduce a runtime revert, so the caller turns this into a clean COMPILE rejection (a safe
   *  over-rejection that kills the miscompile); undefined when the node is not a foldable constant. */
  private evalTypedConst(
    node: ts.Expression,
  ): { value: bigint; type: JethType | 'const' } | { err: string } | { revert: true } | undefined {
    if (ts.isParenthesizedExpression(node)) return this.evalTypedConst(node.expression);
    const lit = this.asIntLiteral(node);
    if (lit !== undefined) return { value: lit, type: 'const' };
    {
      const ec = this.evalEnumConst(node);
      if (ec !== undefined) return ec;
    }
    // type(T).max/.min -> a TYPED value
    if (
      ts.isPropertyAccessExpression(node) &&
      (node.name.text === 'max' || node.name.text === 'min') &&
      ts.isCallExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === 'type' &&
      node.expression.arguments.length === 1 &&
      ts.isIdentifier(node.expression.arguments[0]!)
    ) {
      const t = resolvePrimitiveName((node.expression.arguments[0] as ts.Identifier).text);
      if (!t || !isInteger(t)) return undefined;
      const r = intRange(t);
      return { value: node.name.text === 'max' ? r.max : r.min, type: t };
    }
    // a typed @constant reference
    {
      const rt = this.constTypedRefType(node);
      if (rt !== undefined) {
        const nm = ts.isIdentifier(node) ? node.text : (node as ts.PropertyAccessExpression).name.text;
        const c = this.constantsByName.get(nm)!;
        return { value: c.value as bigint, type: rt };
      }
    }
    // a cast uN(x)/iN(x)
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      const t = resolvePrimitiveName(node.expression.text);
      if (t && isInteger(t) && node.arguments.length === 1) {
        const inner = this.evalTypedConst(node.arguments[0]!);
        if (inner === undefined || 'err' in inner || 'revert' in inner) return inner;
        if (inner.type !== 'const' && isEnum(inner.type) && t.kind !== 'uint') {
          return { err: `explicit conversion not allowed from ${displayName(inner.type)} to ${displayName(t)}` };
        }
        // cast of an int_const: solc REJECTS an out-of-range literal (no truncation of int_const).
        if (inner.type === 'const') {
          if (!this.inRange(inner.value, t))
            return { err: `explicit conversion of constant ${inner.value} out of range for ${displayName(t)}` };
          return { value: inner.value, type: t };
        }
        // cast of a TYPED value: truncate into the target width.
        return { value: this.wrapToType(inner.value, t as { kind: 'uint' | 'int'; bits: number }), type: t };
      }
      return undefined;
    }
    if (ts.isPrefixUnaryExpression(node)) {
      const x = this.evalTypedConst(node.operand);
      if (x === undefined || 'err' in x || 'revert' in x) return x;
      if (x.type !== 'const' && isEnum(x.type)) return { err: `operator cannot be applied to ${displayName(x.type)}` };
      if (node.operator === ts.SyntaxKind.MinusToken) {
        if (x.type === 'const') return { value: -x.value, type: 'const' };
        if (x.type.kind !== 'int') return { err: `unary - cannot be applied to ${displayName(x.type)}` };
        const v = -x.value;
        if (!this.inRange(v, x.type)) return { revert: true };
        return { value: v, type: x.type };
      }
      if (node.operator === ts.SyntaxKind.TildeToken) {
        if (x.type === 'const') return { value: -x.value - 1n, type: 'const' };
        if (x.type.kind === 'uint') return { value: this.wrapToType(~x.value, x.type), type: x.type };
        return { value: -x.value - 1n, type: x.type };
      }
      return undefined;
    }
    if (ts.isBinaryExpression(node)) {
      const op = this.binaryToBinOp(node.operatorToken.kind);
      if (!op) return undefined;
      const a = this.evalTypedConst(node.left);
      if (a === undefined || 'err' in a || 'revert' in a) return a;
      const b = this.evalTypedConst(node.right);
      if (b === undefined || 'err' in b || 'revert' in b) return b;
      if (a.type !== 'const' && isEnum(a.type))
        return { err: `operator '${op}' cannot be applied to ${displayName(a.type)}` };
      if (b.type !== 'const' && isEnum(b.type))
        return { err: `operator '${op}' cannot be applied to ${displayName(b.type)}` };
      // shift: result type = LHS type. A typed LHS truncates to its width; an int_const LHS stays unbounded.
      if (op === '<<' || op === '>>') {
        if (b.value < 0n) return { err: 'negative shift amount' };
        const shifted = op === '<<' ? a.value << b.value : a.value >> b.value;
        if (a.type === 'const') return { value: shifted, type: 'const' };
        return { value: this.wrapToType(shifted, a.type as { kind: 'uint' | 'int'; bits: number }), type: a.type };
      }
      const ct = this.commonConstType(a, b);
      if (ct === null)
        return {
          err: `operator '${op}' cannot be applied to ${displayName((a.type === 'const' ? b.type : a.type) as JethType)} and a mismatched operand`,
        };
      // exponent: result type = base (LHS) type, not common with the exponent.
      const rt: JethType | 'const' = op === '**' ? (a.type === 'const' ? 'const' : a.type) : ct;
      const A = a.value,
        B = b.value;
      let v: bigint;
      switch (op) {
        case '+':
          v = A + B;
          break;
        case '-':
          v = A - B;
          break;
        case '*':
          v = A * B;
          break;
        case '**':
          if (B < 0n) return { err: 'negative exponent in a constant expression' };
          v = A ** B;
          break;
        case '/':
          if (B === 0n) return { revert: true };
          v = A / B;
          break;
        case '%':
          if (B === 0n) return { revert: true };
          v = A % B;
          break;
        case '&':
          v = A & B;
          break;
        case '|':
          v = A | B;
          break;
        case '^':
          v = A ^ B;
          break;
        default:
          return undefined;
      }
      // bitwise: the result stays in the common type (two's complement); no overflow is possible.
      if (op === '&' || op === '|' || op === '^') {
        if (rt === 'const') return { value: v, type: 'const' };
        return { value: this.wrapToType(v, rt as { kind: 'uint' | 'int'; bits: number }), type: rt };
      }
      // arithmetic: a typed result that overflows the result type is a RUNTIME revert (-> compile reject).
      if (rt !== 'const') {
        if (!this.inRange(v, rt)) return { revert: true };
        return { value: v, type: rt };
      }
      return { value: v, type: 'const' };
    }
    return undefined;
  }

  /** If `node` (modulo parentheses) is a bare HEX bigint literal (0x...) with an EVEN digit count,
   *  its source byte width (digits / 2); else undefined. solc converts a hex literal to bytesN iff
   *  this width equals N. (A decimal literal or an odd-digit hex literal never converts.) */
  private hexLiteralBytes(node: ts.Expression): number | undefined {
    let n: ts.Expression = node;
    while (ts.isParenthesizedExpression(n)) n = n.expression;
    if (!ts.isBigIntLiteral(n)) return undefined;
    const raw = n.text.replace(/n$/, '');
    if (!/^0x/i.test(raw)) return undefined;
    const digits = raw.length - 2;
    return digits % 2 === 0 ? digits / 2 : undefined;
  }

  private evalConstInt(node: ts.Expression): bigint | undefined {
    if (ts.isParenthesizedExpression(node)) return this.evalConstInt(node.expression);
    const lit = this.asIntLiteral(node); // a literal or a leading-minus literal
    if (lit !== undefined) return lit;
    // a reference to another integer @constant (bare name when not shadowed by a local, or this.K),
    // and type(T).max/min - both fold to compile-time integers (solc parity).
    const ref = this.constIntRef(node);
    if (ref !== undefined) return ref;
    if (ts.isPrefixUnaryExpression(node)) {
      const x = this.evalConstInt(node.operand);
      if (x === undefined) return undefined;
      if (node.operator === ts.SyntaxKind.MinusToken) return -x;
      // `~x` on an UNTYPED integer constant folds with UNBOUNDED precision to the signed two's-
      // complement value -x-1 (solc: ~ of an int_const yields a signed int_const). It may be negative;
      // the FINAL value is range-checked against the target type at the conversion point (a negative
      // value -> an unsigned type is rejected there, exactly as solc rejects a bare `uint K = ~1`). This
      // lets ~ fold wherever it appears as a SUB-expression, e.g. `(~1) & 3` == -2 & 3 == 2 (solc parity).
      if (node.operator === ts.SyntaxKind.TildeToken) return -x - 1n;
      return undefined;
    }
    if (ts.isBinaryExpression(node)) {
      const op = this.binaryToBinOp(node.operatorToken.kind);
      if (!op) return undefined;
      const a = this.evalConstInt(node.left);
      if (a === undefined) return undefined;
      const b = this.evalConstInt(node.right);
      if (b === undefined) return undefined;
      switch (op) {
        case '+':
          return a + b;
        case '-':
          return a - b;
        case '*':
          return a * b;
        case '**':
          return b < 0n ? undefined : a ** b;
        case '<<':
          return b < 0n ? undefined : a << b;
        case '>>':
          return b < 0n ? undefined : a >> b;
        case '&':
          return a & b;
        case '|':
          return a | b;
        case '^':
          return a ^ b;
        case '/':
          return b === 0n || a % b !== 0n ? undefined : a / b; // solc rejects a fractional constant division
        case '%':
          return b === 0n ? undefined : a % b;
        default:
          return undefined;
      }
    }
    return undefined;
  }

  /** Exact-RATIONAL constant folding for the general expression path, matching solc: a constant
   *  arithmetic expression is evaluated as an unbounded reduced fraction (num/den, den>0), and only
   *  collapsed to an integer (with range/div0/non-integer checks) at the conversion point. This is
   *  what makes `(10n/4n)*4n` == 10 (not 8): division is exact, never truncated mid-expression.
   *  Returns: undefined = NOT a (literal-based) constant expression (leave it to runtime codegen);
   *  {err} = a constant expression solc rejects at compile time (div/mod by zero, negative shift/exp,
   *  a bitwise/shift/% on a non-integer rational); {num,den} = the exact reduced value. */
  private foldConstRational(node: ts.Expression): { num: bigint; den: bigint } | { err: string } | undefined {
    const reduce = (num: bigint, den: bigint): { num: bigint; den: bigint } => {
      if (den < 0n) {
        num = -num;
        den = -den;
      }
      let a = num < 0n ? -num : num,
        b = den;
      while (b) {
        [a, b] = [b, a % b];
      }
      const g = a === 0n ? 1n : a;
      return { num: num / g, den: den / g };
    };
    if (ts.isParenthesizedExpression(node)) return this.foldConstRational(node.expression);
    const lit = this.asIntLiteral(node);
    if (lit !== undefined) return { num: lit, den: 1n };
    // NOTE: deliberately does NOT fold @constant references / type(T).max here. In a function body,
    // solc keeps `type(u16).max + 1` as TYPED (uint16) arithmetic -> a runtime overflow, not a folded
    // constant. Constant folding of these belongs only to the @constant-initializer path (evalConstInt).
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.MinusToken) {
      const x = this.foldConstRational(node.operand);
      if (x === undefined || 'err' in x) return x;
      return reduce(-x.num, x.den);
    }
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.TildeToken) {
      const x = this.foldConstRational(node.operand);
      if (x === undefined || 'err' in x) return x;
      // ~ requires an integer operand: solc rejects `~(rational_const)` (e.g. ~(10/4)). A non-integer
      // intermediate (den != 1) is an error; an exact integer folds to -x-1, like evalConstInt above.
      if (x.den !== 1n) return { err: `operator '~' requires an integer constant operand` };
      return { num: -x.num - 1n, den: 1n };
    }
    if (ts.isBinaryExpression(node)) {
      const op = this.binaryToBinOp(node.operatorToken.kind);
      // Only fold pure arithmetic/bitwise/shift. Comparisons / && / || are not constant-int-folded here.
      if (!op || !['+', '-', '*', '/', '%', '**', '<<', '>>', '&', '|', '^'].includes(op)) return undefined;
      const a = this.foldConstRational(node.left);
      if (a === undefined) return undefined;
      const b = this.foldConstRational(node.right);
      if (b === undefined) return undefined;
      if ('err' in a) return a;
      if ('err' in b) return b;
      switch (op) {
        case '+':
          return reduce(a.num * b.den + b.num * a.den, a.den * b.den);
        case '-':
          return reduce(a.num * b.den - b.num * a.den, a.den * b.den);
        case '*':
          return reduce(a.num * b.num, a.den * b.den);
        case '/':
          if (b.num === 0n) return { err: 'division by zero in a constant expression' };
          return reduce(a.num * b.den, a.den * b.num);
        case '**':
          if (b.den !== 1n) return { err: 'a constant exponent must be an integer' };
          if (b.num < 0n) return { err: 'negative exponent in a constant expression' };
          return reduce(a.num ** b.num, a.den ** b.num);
      }
      // The remaining operators require integer operands (solc rejects them on a non-integer rational).
      if (a.den !== 1n || b.den !== 1n) return { err: `operator '${op}' requires integer constant operands` };
      const A = a.num,
        B = b.num;
      switch (op) {
        case '%':
          return B === 0n ? { err: 'modulo by zero in a constant expression' } : { num: A % B, den: 1n };
        case '<<':
          return B < 0n ? { err: 'negative shift amount' } : { num: A << B, den: 1n };
        case '>>':
          return B < 0n ? { err: 'negative shift amount' } : { num: A >> B, den: 1n };
        case '&':
          return { num: A & B, den: 1n };
        case '|':
          return { num: A | B, den: 1n };
        case '^':
          return { num: A ^ B, den: 1n };
      }
    }
    return undefined;
  }

  /** Materialize a folded reduced rational as an integer `literalInt`, emitting solc-matching
   *  diagnostics (non-integer constant, out of range). `node`/`expected` mirror the literal producers. */
  private literalFromConst(r: { num: bigint; den: bigint }, node: ts.Node, expected?: JethType): Expr | undefined {
    if (r.den !== 1n) {
      this.diags.error(node, 'JETH079', `constant expression ${r.num}/${r.den} is not an integer`);
      return undefined;
    }
    const value = r.num;
    const type = expected && isInteger(expected) && !isEnum(expected) ? expected : value < 0n ? I256 : U256;
    if (!this.inRange(value, type)) {
      this.diags.error(node, 'JETH070', `constant ${value} out of range for ${displayName(type)}`);
      return undefined;
    }
    return { kind: 'literalInt', type, value };
  }

  /** solc treats a hex number literal of 39 to 41 hex digits as "address-like": a 40-digit literal
   *  that passes the EIP-55 checksum is of type `address`, and a 39/41-digit literal or a 40-digit
   *  literal with a bad checksum is a hard error in ANY context (even inside an explicit cast). This
   *  classifies a (possibly parenthesized) bigint literal node accordingly; non-hex / out-of-range
   *  literals are 'plain' (ordinary integers). */
  private classifyAddressHexLiteral(node: ts.Expression): 'plain' | 'address' | { code: string; msg: string } {
    let n: ts.Expression = node;
    while (ts.isParenthesizedExpression(n)) n = n.expression;
    if (!ts.isBigIntLiteral(n)) return 'plain';
    // ts normalizes BigIntLiteral.text to lowercase, so use it only for length; the EIP-55 checksum
    // is case-sensitive and must read the ORIGINAL source spelling via getText().
    const m = /^0[xX]([0-9a-fA-F_]+)n?$/.exec(n.text);
    if (!m) return 'plain';
    const digits = m[1]!.replace(/_/g, '');
    if (digits.length < 39 || digits.length > 41) return 'plain';
    if (digits.length !== 40) {
      return {
        code: 'JETH049',
        msg: `this looks like an address but is not exactly 40 hex digits (it has ${digits.length}); prepend zeros if it is meant to be a number`,
      };
    }
    const rawMatch = /^0[xX]([0-9a-fA-F_]+)n?$/.exec(n.getText());
    const rawDigits = (rawMatch ? rawMatch[1]! : m[1]!).replace(/_/g, '');
    if (!this.isEip55Checksummed(rawDigits)) {
      return {
        code: 'JETH049',
        msg: `this looks like an address but has an invalid EIP-55 checksum (use the checksummed form, or address(...) / a number with leading zeros)`,
      };
    }
    return 'address';
  }

  /** A string/template literal implicitly converts to `bytes` as a hash/abi argument in solc (a string
   *  VARIABLE does not). Returns the `bytes` expected-type for such a literal arg, else undefined. */
  private bytesLiteralExpected(node: ts.Expression): JethType | undefined {
    return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) ? { kind: 'bytes' } : undefined;
  }

  /** solc accepts only a lowercase `0x` hex-literal prefix; an uppercase `0X` is a parser error.
   *  solc also has NO octal (0o/0O) or binary (0b/0B) literal syntax (parser error), but TypeScript's
   *  lexer accepts those and normalizes BigIntLiteral.text to the DECIMAL value (0o17n -> text "15n"),
   *  so the prefix is visible only via getText(). If `node` is any such literal, emit the error and
   *  return true (callers treat its value as a plain int to avoid cascade errors). */
  private rejectUppercaseHexPrefix(node: ts.Expression): boolean {
    let n: ts.Expression = node;
    while (ts.isParenthesizedExpression(n)) n = n.expression;
    if (!ts.isBigIntLiteral(n)) return false;
    const raw = n.getText();
    if (/^0X/.test(raw)) {
      this.diags.error(n, 'JETH049', `uppercase '0X' hex prefix is not allowed; use a lowercase '0x' prefix`);
      return true;
    }
    if (/^0[oObB]/.test(raw)) {
      this.diags.error(
        n,
        'JETH049',
        `octal/binary integer literals (${raw}) are not valid Solidity; use a decimal (0x..) or hex literal`,
      );
      return true;
    }
    return false;
  }

  /** solc allows a single underscore as a digit separator ONLY between two digits; a leading
   *  underscore (after an optional 0x/0b/0o radix prefix), a trailing underscore, or two consecutive
   *  underscores is a parser/syntax error. The TypeScript lexer accepts these and strips the
   *  underscores from BigIntLiteral.text, so the original source spelling must be read via getText().
   *  If `node` (through parens / a leading minus) is such a malformed literal, emit the error and
   *  return true (callers treat the value as a plain int / undefined to avoid cascade errors). */
  private rejectBadUnderscores(node: ts.Expression): boolean {
    let n: ts.Expression = node;
    while (
      ts.isParenthesizedExpression(n) ||
      (ts.isPrefixUnaryExpression(n) && n.operator === ts.SyntaxKind.MinusToken)
    ) {
      n = ts.isParenthesizedExpression(n) ? n.expression : n.operand;
    }
    if (!ts.isBigIntLiteral(n)) return false;
    const digits = n
      .getText()
      .replace(/n$/, '')
      .replace(/^0[xXbBoO]/, '');
    if (/^_|_$|__/.test(digits)) {
      this.diags.error(
        n,
        'JETH049',
        `invalid use of underscores in a number literal; a single underscore is allowed only between digits`,
      );
      return true;
    }
    return false;
  }

  /** EIP-55 mixed-case checksum test for a 40-hex-digit string. Digits 0-9 carry no case and always
   *  pass (so an all-numeric address is valid); each letter must be upper-case iff the corresponding
   *  nibble of keccak256(lowercase-hex-ascii) is >= 8. */
  private isEip55Checksummed(hex40: string): boolean {
    const lower = hex40.toLowerCase();
    const hash = toHex(keccak(lower));
    for (let i = 0; i < 40; i++) {
      const c = hex40[i]!;
      if (c >= '0' && c <= '9') continue;
      const wantUpper = parseInt(hash[i]!, 16) >= 8;
      const isUpper = c >= 'A' && c <= 'F';
      if (wantUpper !== isUpper) return false;
    }
    return true;
  }

  /** If `node` is an integer literal, optionally wrapped in unary minus and/or
   *  parentheses, return its signed value; otherwise undefined. */
  private asIntLiteral(node: ts.Expression): bigint | undefined {
    if (ts.isParenthesizedExpression(node)) return this.asIntLiteral(node.expression);
    if (ts.isBigIntLiteral(node)) return BigInt(node.text.replace(/n$/, ''));
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.MinusToken) {
      const inner = this.asIntLiteral(node.operand);
      return inner === undefined ? undefined : -inner;
    }
    return undefined;
  }

  // ---- helpers -------------------------------------------------------------

  private inRange(value: bigint, type: JethType): boolean {
    if (!isInteger(type)) return type.kind === 'bool';
    const { min, max } = intRange(type);
    return value >= min && value <= max;
  }

  private isComparison(op: BinOp): boolean {
    return op === '<' || op === '>' || op === '<=' || op === '>=' || op === '==' || op === '!=';
  }

  /** solc comparison rule for an out-of-range literal: if one operand is an integer VARIABLE and the
   *  other an integer LITERAL that does not fit the variable's type but fits a WIDER type of the SAME
   *  signedness (the literal's mobile type), both widen to that common type and the comparison is
   *  legal. Returns the widened [left, right] pair, or null to fall back to the normal unify (which
   *  handles the in-range case and rejects a signedness mismatch like `int8 == 200` / `uint8 == -1`). */
  private widenLiteralOperand(left: Expr, right: Expr): [Expr, Expr] | null {
    const fit = (lit: Expr, other: Expr): { common: JethType } | null => {
      if (lit.kind !== 'literalInt' || lit.kind === other.kind || !isInteger(other.type)) return null;
      if (this.inRange(lit.value, other.type)) return null; // fits the variable -> normal path
      const vt = other.type as { kind: 'uint' | 'int'; bits: number };
      if (lit.value >= 0n) {
        if (vt.kind !== 'uint') return null; // positive literal's mobile type is uint; an int var mismatches
        for (let m = vt.bits; m <= 256; m += 8)
          if (lit.value <= (1n << BigInt(m)) - 1n) return { common: { kind: 'uint', bits: m } };
      } else {
        if (vt.kind !== 'int') return null; // negative literal's mobile type is int; a uint var mismatches
        for (let m = vt.bits; m <= 256; m += 8)
          if (lit.value >= -(1n << BigInt(m - 1))) return { common: { kind: 'int', bits: m } };
      }
      return null; // does not fit any type of that signedness -> let unify reject it
    };
    // (var OP lit): widen left=var, right=lit
    const rl = fit(right, left);
    if (rl)
      return [
        { kind: 'cast', type: rl.common, from: left.type, operand: left },
        { ...right, type: rl.common },
      ];
    // (lit OP var): widen left=lit, right=var
    const lr = fit(left, right);
    if (lr)
      return [
        { ...left, type: lr.common },
        { kind: 'cast', type: lr.common, from: right.type, operand: right },
      ];
    return null;
  }

  private isAssignmentOperator(kind: ts.SyntaxKind): boolean {
    return kind === ts.SyntaxKind.EqualsToken || this.compoundToBinOp(kind) !== undefined;
  }

  private compoundToBinOp(kind: ts.SyntaxKind): BinOp | undefined {
    switch (kind) {
      case ts.SyntaxKind.PlusEqualsToken:
        return '+';
      case ts.SyntaxKind.MinusEqualsToken:
        return '-';
      case ts.SyntaxKind.AsteriskEqualsToken:
        return '*';
      case ts.SyntaxKind.SlashEqualsToken:
        return '/';
      case ts.SyntaxKind.PercentEqualsToken:
        return '%';
      case ts.SyntaxKind.AmpersandEqualsToken:
        return '&';
      case ts.SyntaxKind.BarEqualsToken:
        return '|';
      case ts.SyntaxKind.CaretEqualsToken:
        return '^';
      case ts.SyntaxKind.LessThanLessThanEqualsToken:
        return '<<';
      case ts.SyntaxKind.GreaterThanGreaterThanEqualsToken:
        return '>>';
      default:
        return undefined;
    }
  }

  private binaryToBinOp(kind: ts.SyntaxKind): BinOp | undefined {
    switch (kind) {
      case ts.SyntaxKind.PlusToken:
        return '+';
      case ts.SyntaxKind.MinusToken:
        return '-';
      case ts.SyntaxKind.AsteriskToken:
        return '*';
      case ts.SyntaxKind.AsteriskAsteriskToken:
        return '**';
      case ts.SyntaxKind.SlashToken:
        return '/';
      case ts.SyntaxKind.PercentToken:
        return '%';
      case ts.SyntaxKind.LessThanToken:
        return '<';
      case ts.SyntaxKind.GreaterThanToken:
        return '>';
      case ts.SyntaxKind.LessThanEqualsToken:
        return '<=';
      case ts.SyntaxKind.GreaterThanEqualsToken:
        return '>=';
      case ts.SyntaxKind.EqualsEqualsToken:
      case ts.SyntaxKind.EqualsEqualsEqualsToken:
        return '==';
      case ts.SyntaxKind.ExclamationEqualsToken:
      case ts.SyntaxKind.ExclamationEqualsEqualsToken:
        return '!=';
      case ts.SyntaxKind.AmpersandToken:
        return '&';
      case ts.SyntaxKind.BarToken:
        return '|';
      case ts.SyntaxKind.CaretToken:
        return '^';
      case ts.SyntaxKind.LessThanLessThanToken:
        return '<<';
      case ts.SyntaxKind.GreaterThanGreaterThanToken:
        return '>>';
      case ts.SyntaxKind.AmpersandAmpersandToken:
        return '&&';
      case ts.SyntaxKind.BarBarToken:
        return '||';
      default:
        return undefined;
    }
  }
}

export function analyze(
  sourceFile: ts.SourceFile,
  diags: DiagnosticBag,
  diamond?: { name: string; variant: 'array' | 'packed' | 'solidstate' },
): ContractIR | undefined {
  return new Analyzer(sourceFile, diags, diamond).analyze();
}
