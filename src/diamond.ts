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
  variant?: 'array';
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

  // variant arg: @diamond('array') | @diamond() | @diamond. (frozen is a follow-up; reject for now.)
  let variant: 'array' = 'array';
  const dcall = diamondCallOf(cls);
  if (dcall && dcall.arguments.length > 0) {
    if (dcall.arguments.length > 1) {
      err(dcall, 'JETH412', "@diamond(...) takes at most one variant argument (the model, e.g. @diamond('array'))");
    } else {
      const a = dcall.arguments[0]!;
      if (!ts.isStringLiteralLike(a)) err(a, 'JETH412', "@diamond's model argument must be a string literal");
      else if (a.text === 'array') variant = 'array';
      else err(a, 'JETH412', `unknown @diamond model '${a.text}' (only 'array' is supported)`);
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
  const ctorText = ctorNode ? ctorNode.getText(sf) : 'constructor(owner: address) { diamondInit(owner); }';

  // ---- build the synthesized contract source ----
  const body = synthesizeDiamondBody(name, ctorText);

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
