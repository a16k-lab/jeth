// Phase 3 (DIAMOND): `@diamond('array')` source expansion. An EIP-2535 diamond is synthesized as an
// ordinary `@contract` whose members are the diamond-3 storage struct, the diamondCut + 4 loupe fns +
// ERC-165 + ownership, and the DiamondCut/OwnershipTransferred events - reusing the verified storage /
// function / event / namespaced-storage machinery (byte-identity then follows from it). emitRuntime adds
// the selector-routed delegatecall fallback (the router). The expansion is a SOURCE-TEXT transform run
// before parse(), mirroring hoistInClassEnums: the `@diamond` class is replaced in place with the
// synthesized `@contract` (its name + constructor preserved), and the helper structs/enum are appended.
//
// Only TWO pieces are not expressible in JETH and route through synthesis-only builtins lowered in yul.ts:
//   __diamondFacets()                       -> the facets() loupe (builds Facet[] from the split storage)
//   __diamondDelegateInit(_init, _calldata) -> the _init delegatecall in initializeDiamondCut
// and the constructor builtin diamondInit(owner) wires owner + the 4 ERC-165 interface ids + the event.
import ts from 'typescript';

export interface DiamondExpansion {
  /** The rewritten source (the `@diamond` class replaced with the synthesized `@contract`). */
  source: string;
  /** True when a `@diamond` class was found and expanded. */
  expanded: boolean;
  /** Diagnostics from gate validation (positions are into the ORIGINAL source). */
  diagnostics: PreDiagnostic[];
  /** The diamond's name (for the analyzer/yul to flag the deployed contract). */
  name?: string;
  variant?: 'array' | 'packed' | 'solidstate';
}

export interface PreDiagnostic {
  code: string;
  message: string;
  line: number; // 1-based
  column: number; // 1-based
  length: number;
}

// The four ERC-165 interface ids diamondInit registers (spec section "ERC-165 + ownership").
export const IERC165_ID = '0x01ffc9a7';
export const IDIAMOND_CUT_ID = '0x1f931c1c';
export const IDIAMOND_LOUPE_ID = '0x48e2b093';
export const IERC173_ID = '0x7f5828d0';
// The raw mudgen diamond-storage namespace (base = keccak256(of this string), NOT ERC-7201).
export const DIAMOND_STORAGE_NS = 'diamond.standard.diamond.storage';

// ---- solidstate (v0.0.61) namespaces (raw keccak256 bases, one struct each) ----
// The diamond's selector storage is derived from mudgen diamond-2 (the SAME packing) but lives at
// solidstate's own base, and ownership / supported interfaces live in SEPARATE namespaces (NOT in the
// diamond struct, unlike mudgen). The field ORDER below matches solidstate's struct order exactly so the
// raw storage slots are byte-identical to a solc solidstate v0.0.61 mirror.
export const SS_DIAMOND_NS = 'solidstate.contracts.storage.DiamondBase'; // selectorInfo, selectorCount, selectorSlugs, fallbackAddress
export const SS_OWNABLE_NS = 'solidstate.contracts.storage.Ownable'; // owner
export const SS_SAFEOWNABLE_NS = 'solidstate.contracts.storage.SafeOwnable'; // nomineeOwner
export const SS_ERC165_NS = 'solidstate.contracts.storage.ERC165Base'; // supportedInterfaces

/** Detect + expand a `@diamond(...)` class. Returns the (possibly unchanged) source, an `expanded`
 *  flag, gate diagnostics, and the diamond's name/variant. A non-diamond file is returned untouched. */
export function expandDiamond(source: string, fileName: string): DiamondExpansion {
  const sf = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const diags: PreDiagnostic[] = [];
  const at = (node: ts.Node): Pick<PreDiagnostic, 'line' | 'column' | 'length'> => {
    const start = node.getStart(sf);
    const { line, character } = sf.getLineAndCharacterOfPosition(start);
    return { line: line + 1, column: character + 1, length: node.getWidth(sf) };
  };
  const err = (node: ts.Node, code: string, message: string) => diags.push({ code, message, ...at(node) });

  let diamondClass: ts.ClassDeclaration | undefined;
  const visit = (n: ts.Node): void => {
    if (ts.isClassDeclaration(n) && decoratorNamesOf(n).includes('diamond')) {
      if (diamondClass) err(n, 'JETH041', 'multiple @diamond classes per file are not supported');
      else diamondClass = n;
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(sf, visit);

  if (!diamondClass) return { source, expanded: false, diagnostics: diags };

  const cls = diamondClass;
  const name = cls.name?.text ?? 'Diamond';

  // ---- gates (JETH41x) ----
  if (decoratorNamesOf(cls).includes('facet')) err(cls, 'JETH411', 'a class cannot be both @diamond and @facet');
  if (decoratorNamesOf(cls).includes('contract'))
    err(cls, 'JETH411', 'a @diamond class must not also be @contract (the @contract surface is synthesized)');

  // variant arg: @diamond('array') | @diamond('packed') | @diamond('solidstate') | @diamond() | @diamond.
  let variant: 'array' | 'packed' | 'solidstate' = 'array';
  const dcall = diamondCallOf(cls);
  if (dcall && dcall.arguments.length > 0) {
    if (dcall.arguments.length > 1) {
      err(dcall, 'JETH412', "@diamond(...) takes at most one variant argument (the model, e.g. @diamond('array'))");
    } else {
      const a = dcall.arguments[0]!;
      if (!ts.isStringLiteralLike(a)) err(a, 'JETH412', "@diamond's model argument must be a string literal");
      else if (a.text === 'array') variant = 'array';
      else if (a.text === 'packed') variant = 'packed';
      else if (a.text === 'solidstate') variant = 'solidstate';
      else
        err(a, 'JETH412', `unknown @diamond model '${a.text}' (only 'array', 'packed' and 'solidstate' are supported)`);
    }
  }

  // member gates: no @state / @storage, no @external method, no user @receive/@fallback.
  let ctorNode: ts.ConstructorDeclaration | undefined;
  for (const m of cls.members) {
    if (ts.isPropertyDeclaration(m)) {
      const d = decoratorNamesOf(m);
      if (d.includes('state') || d.includes('storage') || d.includes('constant') || d.includes('immutable'))
        err(m, 'JETH413', 'a @diamond class may not declare storage fields (the diamond-3 storage is synthesized)');
      else err(m, 'JETH413', 'a @diamond class may not declare fields (the whole surface is synthesized)');
    } else if (ts.isMethodDeclaration(m)) {
      const d = decoratorNamesOf(m);
      if (d.includes('receive') || d.includes('fallback'))
        err(
          m,
          'JETH413',
          'a @diamond class may not declare a @receive/@fallback entry (the router fallback is synthesized)',
        );
      else if (d.includes('event') || d.includes('error') || d.includes('modifier'))
        err(m, 'JETH413', 'a @diamond class may not declare events/errors/modifiers (synthesized)');
      else
        err(
          m,
          'JETH413',
          `a @diamond class may not declare a method ('${methodName(m)}'): the entire surface is synthesized; write only the constructor calling diamondInit(owner)`,
        );
    } else if (ts.isConstructorDeclaration(m)) {
      if (ctorNode) err(m, 'JETH300', 'a contract may declare at most one constructor');
      else ctorNode = m;
    }
  }
  if (cls.heritageClauses && cls.heritageClauses.length > 0)
    err(cls, 'JETH413', 'a @diamond class may not extend another contract (the surface is synthesized)');

  // The constructor text is preserved verbatim (diamondInit is a recognized constructor builtin). If the
  // user omitted a constructor, synthesize a no-arg one that leaves owner unset (degenerate, but valid).
  // The solidstate model uses diamondInitSolidstate (its own interface ids + the Ownable-namespace owner).
  const defaultCtorInit = variant === 'solidstate' ? 'diamondInitSolidstate(owner)' : 'diamondInit(owner)';
  const ctorText = ctorNode ? ctorNode.getText(sf) : `constructor(owner: address) { ${defaultCtorInit}; }`;

  // ---- build the synthesized contract source ----
  const body =
    variant === 'solidstate'
      ? synthesizeDiamondBodySolidstate(name, ctorText)
      : variant === 'packed'
        ? synthesizeDiamondBodyPacked(name, ctorText)
        : synthesizeDiamondBody(name, ctorText);

  // Replace the `@diamond` class span (including its leading decorators) with the synthesized contract.
  const replaceStart = cls.getStart(sf); // start of decorators
  const replaceEnd = cls.getEnd();
  const before = source.slice(0, replaceStart);
  const after = source.slice(replaceEnd);
  const rewritten = before + body.contract + after + '\n' + body.helpers + '\n';

  return { source: rewritten, expanded: diags.length === 0, diagnostics: diags, name, variant };
}

/** The synthesized diamond `@contract` body + the helper structs (appended at top level). The storage
 *  field names are underscore-prefixed to avoid the JETH function/field name clash (solc reaches them
 *  through a library struct, JETH through `this.`); the slots are layout-derived, so the names are not
 *  observable. The diamondCut add/replace/remove loops are INLINED (a calldata struct-element's dyn-array
 *  field cannot be passed to a helper), which is purely structural - the storage writes/reverts/events
 *  are byte-identical to the mudgen helper form. */
function synthesizeDiamondBody(name: string, ctorText: string): { contract: string; helpers: string } {
  const NS = `@storage('${DIAMOND_STORAGE_NS}', 'raw')`;
  const contract = `@contract class ${name} {
  ${NS} _sel2facet: mapping<bytes4, __DiamondFAP>;
  ${NS} _facetSelectors: mapping<address, __DiamondFFS>;
  ${NS} _facetAddresses: address[];
  ${NS} _supportedInterfaces: mapping<bytes4, bool>;
  ${NS} _contractOwner: address;

  @event OwnershipTransferred(@indexed previousOwner: address, @indexed newOwner: address): void;
  @event DiamondCut(_diamondCut: __DiamondFacetCut[], _init: address, _calldata: bytes): void;

  ${ctorText}

  @external @view owner(): address { return this._contractOwner; }
  @external transferOwnership(newOwner: address): void {
    require(msg.sender == this._contractOwner, "LibDiamond: Must be contract owner");
    const __prev: address = this._contractOwner;
    this._contractOwner = newOwner;
    emit(OwnershipTransferred(__prev, newOwner));
  }

  @external @view supportsInterface(__id: bytes4): bool { return this._supportedInterfaces[__id]; }

  @external @view facets(): __DiamondFacet[] { return __diamondFacets(); }
  @external @view facetFunctionSelectors(__facet: address): bytes4[] {
    const __n: u256 = this._facetSelectors[__facet].functionSelectors.length;
    const __out: bytes4[] = new Array<bytes4>(__n);
    for (let __i: u256 = 0n; __i < __n; __i = __i + 1n) { __out[__i] = this._facetSelectors[__facet].functionSelectors[__i]; }
    return __out;
  }
  @external @view facetAddresses(): address[] { return this._facetAddresses; }
  @external @view facetAddress(__functionSelector: bytes4): address {
    return this._sel2facet[__functionSelector].facetAddress;
  }

  @external diamondCut(_diamondCut: __DiamondFacetCut[], _init: address, _calldata: bytes): void {
    require(msg.sender == this._contractOwner, "LibDiamond: Must be contract owner");
    for (let __c: u256 = 0n; __c < _diamondCut.length; __c = __c + 1n) {
      const __facet: address = _diamondCut[__c].facetAddress;
      const __action: u8 = _diamondCut[__c].action;
      const __m: u256 = _diamondCut[__c].functionSelectors.length;
      if (__action == 0n) {
        require(__m > 0n, "LibDiamondCut: No selectors in facet to cut");
        require(__facet != address(0n), "LibDiamondCut: Add facet can't be address(0)");
        let __sp: u96 = u96(this._facetSelectors[__facet].functionSelectors.length);
        if (__sp == 0n) { this.__addFacet(__facet); }
        for (let __j: u256 = 0n; __j < __m; __j = __j + 1n) {
          const __sel: bytes4 = _diamondCut[__c].functionSelectors[__j];
          const __old: address = this._sel2facet[__sel].facetAddress;
          require(__old == address(0n), "LibDiamondCut: Can't add function that already exists");
          this.__addFunction(__sel, __sp, __facet);
          __sp = __sp + 1n;
        }
      } else if (__action == 1n) {
        require(__m > 0n, "LibDiamondCut: No selectors in facet to cut");
        require(__facet != address(0n), "LibDiamondCut: Add facet can't be address(0)");
        let __sp: u96 = u96(this._facetSelectors[__facet].functionSelectors.length);
        if (__sp == 0n) { this.__addFacet(__facet); }
        for (let __j: u256 = 0n; __j < __m; __j = __j + 1n) {
          const __sel: bytes4 = _diamondCut[__c].functionSelectors[__j];
          const __old: address = this._sel2facet[__sel].facetAddress;
          require(__old != __facet, "LibDiamondCut: Can't replace function with same function");
          require(__old != address(0n), "LibDiamondCut: Can't replace function that doesn't exist");
          require(__old != address(this), "LibDiamondCut: Can't replace immutable function");
          this.__removeFunction(__old, __sel);
          this.__addFunction(__sel, __sp, __facet);
          __sp = __sp + 1n;
        }
      } else if (__action == 2n) {
        require(__m > 0n, "LibDiamondCut: No selectors in facet to cut");
        require(__facet == address(0n), "LibDiamondCut: Remove facet address must be address(0)");
        for (let __j: u256 = 0n; __j < __m; __j = __j + 1n) {
          const __sel: bytes4 = _diamondCut[__c].functionSelectors[__j];
          const __old: address = this._sel2facet[__sel].facetAddress;
          this.__removeFunction(__old, __sel);
        }
      } else {
        revert("LibDiamondCut: Incorrect FacetCutAction");
      }
    }
    emit(DiamondCut(_diamondCut, _init, _calldata));
    __diamondDelegateInit(_init, _calldata);
  }

  __addFacet(__facet: address): void {
    require(__facet.code.length > 0n, "LibDiamondCut: New facet has no code");
    this._facetSelectors[__facet].facetAddressPosition = this._facetAddresses.length;
    this._facetAddresses.push(__facet);
  }
  __addFunction(__sel: bytes4, __sp: u96, __facet: address): void {
    this._sel2facet[__sel].functionSelectorPosition = __sp;
    this._facetSelectors[__facet].functionSelectors.push(__sel);
    this._sel2facet[__sel].facetAddress = __facet;
  }
  __removeFunction(__facet: address, __sel: bytes4): void {
    require(__facet != address(0n), "LibDiamondCut: Can't remove function that doesn't exist");
    require(__facet != address(this), "LibDiamondCut: Can't remove immutable function");
    const __sp: u256 = u256(this._sel2facet[__sel].functionSelectorPosition);
    const __lastSp: u256 = this._facetSelectors[__facet].functionSelectors.length - 1n;
    if (__sp != __lastSp) {
      const __lastSel: bytes4 = this._facetSelectors[__facet].functionSelectors[__lastSp];
      this._facetSelectors[__facet].functionSelectors[__sp] = __lastSel;
      this._sel2facet[__lastSel].functionSelectorPosition = u96(__sp);
    }
    this._facetSelectors[__facet].functionSelectors.pop();
    delete this._sel2facet[__sel];
    if (__lastSp == 0n) {
      const __lastFap: u256 = this._facetAddresses.length - 1n;
      const __fap: u256 = this._facetSelectors[__facet].facetAddressPosition;
      if (__fap != __lastFap) {
        const __lastFa: address = this._facetAddresses[__lastFap];
        this._facetAddresses[__fap] = __lastFa;
        this._facetSelectors[__lastFa].facetAddressPosition = __fap;
      }
      this._facetAddresses.pop();
      delete this._facetSelectors[__facet].facetAddressPosition;
    }
  }
}`;

  const helpers = `@struct class __DiamondFAP { facetAddress: address; functionSelectorPosition: u96; }
@struct class __DiamondFFS { functionSelectors: bytes4[]; facetAddressPosition: u256; }
@struct class __DiamondFacet { facetAddress: address; functionSelectors: bytes4[]; }
@struct class __DiamondFacetCut { facetAddress: address; action: u8; functionSelectors: bytes4[]; }`;

  return { contract, helpers };
}

/** The synthesized @diamond('packed') @contract body + helper structs (diamond-2 / diamond-2-hardhat
 *  layout). The diamond-2 storage struct lives at the SAME raw keccak base as the array model:
 *    mapping(bytes4 => bytes32) facets;          // base+0  (facet addr in HIGH 20 bytes | uint16 pos LOW)
 *    mapping(uint256 => bytes32) selectorSlots;  // base+1  (8 packed bytes4 selectors per slot)
 *    uint16 selectorCount;                       // base+2  (right-aligned, alone in its slot)
 *    mapping(bytes4 => bool) supportedInterfaces;// base+3
 *    address contractOwner;                      // base+4
 *  diamondCut and all 4 loupe functions route through raw-Yul builtins (src/yul.ts) because the packed
 *  bit-math (CLEAR_ADDRESS_MASK/CLEAR_SELECTOR_MASK, slot flush on the 8th selector, swap-into-gap
 *  removal) and the loupe's over-allocate-then-mstore-shrink reconstruction are not expressible in plain
 *  JETH. Everything else (owner gate, emit DiamondCut, the _init delegatecall, ERC-165, ownership,
 *  diamondInit) is byte-identical to the array model and reuses the same machinery. */
function synthesizeDiamondBodyPacked(name: string, ctorText: string): { contract: string; helpers: string } {
  const NS = `@storage('${DIAMOND_STORAGE_NS}', 'raw')`;
  const contract = `@contract class ${name} {
  ${NS} _facets: mapping<bytes4, bytes32>;
  ${NS} _selectorSlots: mapping<u256, bytes32>;
  ${NS} _selectorCount: u16;
  ${NS} _supportedInterfaces: mapping<bytes4, bool>;
  ${NS} _contractOwner: address;

  @event OwnershipTransferred(@indexed previousOwner: address, @indexed newOwner: address): void;
  @event DiamondCut(_diamondCut: __DiamondFacetCut[], _init: address, _calldata: bytes): void;

  ${ctorText}

  @external @view owner(): address { return this._contractOwner; }
  @external transferOwnership(newOwner: address): void {
    require(msg.sender == this._contractOwner, "LibDiamond: Must be contract owner");
    const __prev: address = this._contractOwner;
    this._contractOwner = newOwner;
    emit(OwnershipTransferred(__prev, newOwner));
  }

  @external @view supportsInterface(__id: bytes4): bool { return this._supportedInterfaces[__id]; }

  @external @view facets(): __DiamondFacet[] { return __diamondFacetsPacked(); }
  @external @view facetFunctionSelectors(__facet: address): bytes4[] { return __diamondFacetSelectorsPacked(__facet); }
  @external @view facetAddresses(): address[] { return __diamondFacetAddressesPacked(); }
  @external @view facetAddress(__functionSelector: bytes4): address {
    return address(bytes20(this._facets[__functionSelector]));
  }

  @external diamondCut(_diamondCut: __DiamondFacetCut[], _init: address, _calldata: bytes): void {
    require(msg.sender == this._contractOwner, "LibDiamond: Must be contract owner");
    __diamondCutPacked();
    emit(DiamondCut(_diamondCut, _init, _calldata));
    __diamondDelegateInit(_init, _calldata);
  }
}`;

  const helpers = `@struct class __DiamondFacet { facetAddress: address; functionSelectors: bytes4[]; }
@struct class __DiamondFacetCut { facetAddress: address; action: u8; functionSelectors: bytes4[]; }`;

  return { contract, helpers };
}

/** The synthesized @diamond('solidstate') @contract body + helper structs (solidstate v0.0.61 layout).
 *  solidstate's on-chain selector storage is DERIVED FROM mudgen diamond-2 (the SAME 8-selectors-per-slug
 *  packing + address-in-high-20-bytes facet record), so the cut + the four loupe reconstructors are the
 *  packed model's raw-Yul builtins. What is DISTINCTIVE to solidstate (and built here):
 *    - its OWN storage bases (NOT mudgen's "diamond.standard.diamond.storage") in solidstate's field order:
 *        DiamondBase ns: selectorInfo(0), selectorCount(1), selectorSlugs(2), fallbackAddress(3)
 *      with ownership + supported interfaces in SEPARATE namespaces (Ownable.owner, SafeOwnable.nomineeOwner,
 *      ERC165Base.supportedInterfaces) instead of inside the diamond struct.
 *    - the settable DEFAULT FALLBACK ADDRESS: getFallbackAddress()/setFallbackAddress(address) (owner-gated);
 *      the router delegatecalls the stored fallback on a selector MISS when it is non-zero (the headline feat).
 *    - SafeOwnable 2-step ownership: transferOwnership(account) sets the NOMINEE (no transfer, no event),
 *      acceptOwnership() finalizes (the nominee becomes owner, emits OwnershipTransferred, clears the nominee).
 *  The cut uses __diamondCutSolidstate() (solidstate's custom-error revert set + require order); everything
 *  else routes through the SAME packed loupe + the SAME storage field names (_facets/_selectorSlots/
 *  _selectorCount) so the diamondSlot(name) lookups in yul.ts are unchanged - only the slots (= solidstate's
 *  declaration order) differ. */
function synthesizeDiamondBodySolidstate(name: string, ctorText: string): { contract: string; helpers: string } {
  const DS = `@storage('${SS_DIAMOND_NS}', 'raw')`;
  const OW = `@storage('${SS_OWNABLE_NS}', 'raw')`;
  const SO = `@storage('${SS_SAFEOWNABLE_NS}', 'raw')`;
  const I165 = `@storage('${SS_ERC165_NS}', 'raw')`;
  // The selector record fields keep the packed model's NAMES (the loupe/cut builtins read them by name) but
  // are declared in solidstate's struct ORDER: selectorInfo(0), selectorCount(1), selectorSlugs(2),
  // fallbackAddress(3). _facets == selectorInfo, _selectorSlots == selectorSlugs.
  const contract = `@contract class ${name} {
  ${DS} _facets: mapping<bytes4, bytes32>;
  ${DS} _selectorCount: u16;
  ${DS} _selectorSlots: mapping<u256, bytes32>;
  ${DS} _fallbackAddress: address;
  ${OW} _contractOwner: address;
  ${SO} _nomineeOwner: address;
  ${I165} _supportedInterfaces: mapping<bytes4, bool>;

  @event OwnershipTransferred(@indexed previousOwner: address, @indexed newOwner: address): void;
  @event DiamondCut(_diamondCut: __DiamondFacetCut[], _init: address, _calldata: bytes): void;

  ${ctorText}

  @external @view owner(): address { return this._contractOwner; }
  @external @view nomineeOwner(): address { return this._nomineeOwner; }

  // SafeOwnable 2-step: transferOwnership sets the NOMINEE only (no transfer, no event); acceptOwnership
  // (nominee-gated) finalizes - the nominee becomes owner (emits OwnershipTransferred) and the nominee clears.
  @external transferOwnership(account: address): void {
    if (msg.sender != this._contractOwner) { __revertSelector(0x2f7a8ee1n); } // Ownable__NotOwner()
    this._nomineeOwner = account;
  }
  @external acceptOwnership(): void {
    if (msg.sender != this._nomineeOwner) { __revertSelector(0xefd1052dn); } // SafeOwnable__NotNomineeOwner()
    const __prev: address = this._contractOwner;
    this._contractOwner = msg.sender;
    emit(OwnershipTransferred(__prev, msg.sender));
    this._nomineeOwner = address(0n);
  }

  // Default fallback address: getFallbackAddress()/setFallbackAddress(address) (owner-gated). The router
  // delegatecalls this address on a selector MISS when it is non-zero.
  @external @view getFallbackAddress(): address { return this._fallbackAddress; }
  @external setFallbackAddress(__fallbackAddress: address): void {
    if (msg.sender != this._contractOwner) { __revertSelector(0x2f7a8ee1n); } // Ownable__NotOwner()
    this._fallbackAddress = __fallbackAddress;
  }

  @external @view supportsInterface(__id: bytes4): bool { return this._supportedInterfaces[__id]; }

  @external @view facets(): __DiamondFacet[] { return __diamondFacetsPacked(); }
  @external @view facetFunctionSelectors(__facet: address): bytes4[] { return __diamondFacetSelectorsPacked(__facet); }
  @external @view facetAddresses(): address[] { return __diamondFacetAddressesPacked(); }
  @external @view facetAddress(__functionSelector: bytes4): address {
    return address(bytes20(this._facets[__functionSelector]));
  }

  @external diamondCut(_diamondCut: __DiamondFacetCut[], _init: address, _calldata: bytes): void {
    if (msg.sender != this._contractOwner) { __revertSelector(0x2f7a8ee1n); } // Ownable__NotOwner()
    __diamondCutSolidstate();
    emit(DiamondCut(_diamondCut, _init, _calldata));
    __diamondDelegateInit(_init, _calldata);
  }
}`;

  const helpers = `@struct class __DiamondFacet { facetAddress: address; functionSelectors: bytes4[]; }
@struct class __DiamondFacetCut { facetAddress: address; action: u8; functionSelectors: bytes4[]; }`;

  return { contract, helpers };
}

// ---- small AST helpers (self-contained; the analyzer's parser helpers aren't imported to keep this
// module free of a circular dependency with the main pipeline). ----
function decoratorNamesOf(node: ts.Node): string[] {
  if (!ts.canHaveDecorators(node)) {
    // ConstructorDeclaration: TS guards it out, but decorators are still recorded.
    const got = ts.getDecorators(node as unknown as ts.HasDecorators) ?? [];
    return got.map(decName).filter((s): s is string => !!s);
  }
  return (ts.getDecorators(node) ?? []).map(decName).filter((s): s is string => !!s);
}
function decName(d: ts.Decorator): string | undefined {
  const e = d.expression;
  if (ts.isIdentifier(e)) return e.text;
  if (ts.isCallExpression(e) && ts.isIdentifier(e.expression)) return e.expression.text;
  return undefined;
}
function diamondCallOf(cls: ts.ClassDeclaration): ts.CallExpression | undefined {
  for (const d of ts.getDecorators(cls) ?? []) {
    if (
      ts.isCallExpression(d.expression) &&
      ts.isIdentifier(d.expression.expression) &&
      d.expression.expression.text === 'diamond'
    )
      return d.expression;
  }
  return undefined;
}
function methodName(m: ts.MethodDeclaration): string {
  return ts.isIdentifier(m.name) ? m.name.text : '<method>';
}
