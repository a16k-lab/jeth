# HANDOFF: finish the pointer-headed `Arr<In,N>` coverage proof

**Goal:** guarantee no consumer of the pointer-headed `Arr<In,N>` (fixed array of a *static* struct)
memory image mis-handles it (a flat-copy of the pointer words = a payload-dropping miscompile). We proved
coverage is complete-by-construction (finite enumerated consumer sites, each exercised by a run+decode
differential test) and fixed 8 such consumers; **one remains (the 9th)**, plus a loop-to-convergence.

## State at handoff

- Branch `main`, pushed to origin. Last green HEAD before this doc: **`18d6ae6`** (suite **393 files /
  3599 tests** green, `tsc --noEmit` clean).
- ABSOLUTE BAR (never violate): **zero miscompiles, zero over-acceptances**. A clean reject / loud Panic
  always beats wrong bytes. Judge ONLY via the differential harness (behavioral byte-identity vs solc
  0.8.35 **legacy** pipeline; JETH bytecode never equals solc).
- `Arr<In,N>` (In a static struct) is **pointer-headed** in memory (N absolute-pointer words -> per-element
  images). This is **correct** - it matches solc, including memory reference/aliasing semantics
  (`m[1]=m[0]; m[0].a=7` -> `m[1].a==7`). **DO NOT flatten it** (investigated + rejected; a flat value-copy
  layout would miscompile aliasing - see `docs/flat-static-struct-array-spec.md`). The fix for a bad
  consumer is always to make *that consumer* pointer-aware (deref each element pointer via `abiEncFromMem` /
  `abiDec*ToImage`), byte-identical - never to change the representation.

## STEP 1 - Fix the 9th consumer (a real miscompile on `18d6ae6`)

**Shape:** a multi-value TUPLE RETURN whose component is a FIXED-ARRAY ELEMENT `m[i]` of type `Arr<In,N>`
(source `Arr<Arr<In,N>,M>` or `Arr<In,N>[]`). Sibling of commit `e33d131` (which fixed the plain-local
branch of the same encoder).

Repro (JETH) - both compile+run, JETH bytes wrong:
```
@struct class In { x: u256; y: u256 }
@contract class C {
  @external @pure f(): [u256, Arr<In,2>] {
    let m: Arr<Arr<In,2>,2> = [[In(11n,12n),In(13n,14n)],[In(15n,16n),In(17n,18n)]];
    return [42n, m[1n]];
  }
}
```
solc mirror (contract `C`): `struct In { uint256 x; uint256 y; } contract C { function f() external pure
returns(uint256, In[2] memory){ In[2][2] memory m=[[In(11,12),In(13,14)],[In(15,16),In(17,18)]]; return
(42, m[1]); } }`. solc returns `[42,15,16,17,18]` (Arr<In,2> INLINED); JETH returns
`[42, 0xa0, 0, 0, 0, 15,16,17,18]` (a bogus dynamic offset `0xa0` + zero head + mislocated tail).

Also miscompiles for a dynamic-outer source `Arr<In,2>[]` element. Controls that MATCH (localize it,
keep them matching): `abi.encode(m[1n])` single-arg; `return [42n, plainLocalArr]` (the `e33d131` branch).

**Root cause:** `src/yul.ts` multi-value tuple-return encoder - the branch handling an `arrayValue`
component whose base is `memArray`/`memArrayExpr` (search near the `e33d131` change; the finding cited
~L4095-4123, condition roughly `t.kind==='array' && values[i].kind==='arrayValue' && base.kind in
{memArray,memArrayExpr}`). It unconditionally writes a dynamic offset word, with NO
`isDynamicType(t)`/`t.length===undefined` guard, so an ABI-static fixed array is offset-encoded as dynamic.

**Fix (byte-identical, mirror `e33d131`):** in that branch, when the component is an ABI-static fixed array
(`isStaticStructFixedLeafArray(t)` / `isStaticType(t) && t.length!==undefined`), take the INLINE path -
materialize the element image pointer and `abiEncFromMem` it inline at the head cursor (N*abiHeadWords(In)
words, no offset word; fix the head-word accounting), instead of the dynamic-offset path. Do NOT touch: the
plain-local branch (`e33d131`), the single-arg `abi.encode` path, or a genuinely-dynamic component
(`Arr<string,N>` element, a dyn array) which MUST still get an offset word. Read `git show e33d131` first.

Verify (harness, distinct non-zero values, decode every word): `fNest`/`fDynOuter` byte-identical; element
at first/middle/last tuple positions; In3 (3-field); nested `Arr<Arr<Arr<In,2>,2>,2>` element; a MIXED tuple
`[42, m[i]:Arr<In,2>, "str"]` (static-inline + dynamic-offset in one tuple - head/tail accounting correct);
value-array `Arr<u256,2>` element in a tuple (PIN solc; fix if broken too); the `e33d131` plain-local +
single-arg controls still MATCH. A `git stash` of the fix must make the new test FAIL (non-vacuity).

**NOTE:** an in-flight background workflow may have produced this fix in a git worktree during the prior
session; you won't have its SHA, so just redo it from the above (idempotent).

## STEP 2 - Loop the coverage proof to convergence

Re-run the completeness coverage proof against the fixed tree. Each round enumerates the finite codec
consumer sites + exhaustively differential-tests the (source x consumer x shape) matrix + reports any
MISCOMPILE / OVER-ACCEPTANCE. Fix each finding the same way (byte-identical pointer-aware consumer, or a
clean reject that matches solc-legacy), commit + suite + push, then re-run. Repeat until it returns
**FULLY-COVERED-CLEAN** (0 violations across all slices, no uncovered sites). Then commit the per-consumer
regression tests (several already exist: `flat-static-struct-array-stage0-matrix`,
`ext-call-result-static-struct-array-*`, `multi-return-static-struct-array`, `calldata-struct-array-internal-arg`,
etc.).

The consumer axis to cover (this is where leaks hide, not the shape axis): every SOURCE {array literal, `new
Array<In>(n)`, calldata param, @state storage, memory local, internal-call result, external-call result,
`abi.decode(b,T)`, struct field} x every CONSUMER {return, `abi.encode`/`encodePacked`/`encodeWithSelector`/
`encodeCall`, event indexed+data, `revert`/custom-error arg, internal-call arg (+2-hop, callee-mutates,
callee-returns), external-call arg, tuple return (+element source), struct-field construct+read, storage
assign, push, mapping value, `@external` getter, ternary, for-of, delete, element/field read+write, `.length`,
nested `Arr<Arr<In,N>,M>`, struct-with-`Arr<In,N>`-field} x shapes {In 2/3-field, nested-static-struct element,
N=1/2/3, preceding/following field offset}. COEXISTENCE guards that must stay pointer-headed + byte-identical:
dynamic-outer `In[]`, `Arr<DynIn,N>`, value arrays `Arr<u256,N>`, `Arr<string,N>`.

## Execution recipe (used all session)

1. `export PATH="$HOME/.nvm/versions/node/v22.22.2/bin:$PATH"` then run everything via `npx tsx` / `npx vitest`.
2. Differential harness (recreate at a scratch path if the session scratchpad is gone - content in the
   Appendix). `diff(label, JETHsrc, SOLsrc, calls, {value})` -> `{class}` in
   `MATCH|BOTH-REJECT|OVER-REJECTION|OVER-ACCEPTANCE|DIVERGE`; `DIVERGE.diffs[i].cls` includes
   `MISCOMPILE(both-ok,diff-bytes)`. `compileJeth(src)`/`compileSol(src,'C')` for accept/reject. `calls =
   [[sig, argsHex]]`, `W(n)=pad32`, `sel(sig)=selector`. solc contract MUST be named `C`.
3. `graphify query "<question>"` BEFORE reading source; `graphify update .` AFTER editing.
4. Make the fix -> `npx tsc --noEmit` clean (esbuild/vitest does NOT typecheck - run tsc explicitly) -> add a
   non-vacuous run+decode regression test -> `npx vitest run --hookTimeout=120000 --testTimeout=120000` ->
   **gate the push on a GREEN suite in a SEPARATE step** (do not `git push` in the same command as the suite)
   -> `graphify update .` -> `git push`.
5. Prefer worktree-isolated fix + independent adversarial-verify agents (the verifier repeatedly caught
   mistakes my own fixes introduced); cherry-pick the clean commit onto `main`; full suite; push.

## Traps / lessons (make zero mistakes)

- "both compile" != byte-identical - always RUN + DECODE with DISTINCT non-zero values (a zero / raw-pointer
  tail must not masquerade as a match).
- VACUOUS-SELECTOR trap: a struct / array-of-struct external param dispatches on the EXPANDED-TUPLE selector
  (`f((uint256,(uint256,uint256)[2]))`, NOT `f(S)`). A wrong selector -> both revert-empty vacuously. Build
  values INSIDE functions where possible + anchor with a decoded scalar.
- solc LEGACY `UnimplementedFeatureError` (e.g. mem/cd struct-array -> storage) is the reference's hard wall;
  there is NO viaIR reference in the harness, so JETH must REJECT such shapes (code `JETH470`) to match
  legacy - accepting them (even with plausible bytes) is an over-acceptance.
- Existing reject codes in this family: `JETH470` (mem/cd -> storage struct-array copy, all mutation entry
  points), `JETH465` (inline struct-ctor with a pointer-headed field, transient - could be lifted later once
  the consumer is proven; kept as a safe reject for now). Next free diag code: `JETH471`.
- Every JETH integer literal needs the `n` suffix (bare `0` in an index gives `JETH071`, masquerades as a
  feature gap).
- Deviation already documented (do NOT "fix"): `@pure` may call `this.internalMethod()` (JETH's `this.f()` on
  an internal `f` is an internal call; solc requires >=view). Benign, documented in
  `docs/distinctive-features.md`.

## Appendix - differential harness (`diff.mjs`)

Recreate this file in a scratch dir and import it from your probes; adjust the 4 absolute import paths to your
JETH checkout.
```js
import { compile } from '/Users/farajioranj/Desktop/JETH/src/compile.js';
import { Harness, pad32 } from '/Users/farajioranj/Desktop/JETH/src/evm.js';
import { functionSelector } from '/Users/farajioranj/Desktop/JETH/src/selectors.js';
import { compileSolidity } from '/Users/farajioranj/Desktop/JETH/test/_solidity.js';
export const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
export const W = (n) => pad32(BigInt(n));
export const sel = (s) => functionSelector(s);
export function compileJeth(src) {
  try { return { ok: true, bytecode: compile(src, { fileName: 'C.jeth' }).creationBytecode, codes: [] }; }
  catch (e) { return { ok: false, bytecode: null, codes: (e?.diagnostics ?? []).map((d) => d.code) }; }
}
export function compileSol(src, name = 'C') {
  try { return { ok: true, creation: compileSolidity(SPDX + src, name).creation }; }
  catch (e) { return { ok: false, creation: null, err: String(e?.message ?? e).slice(0, 200) }; }
}
export async function diff(label, J, S, calls, { value, name = 'C' } = {}) {
  const cj = compileJeth(J); const cs = compileSol(S, name); const callsArr = calls || [];
  const runAll = async (addr, h) => {
    const out = [];
    for (const [sig, args] of callsArr) {
      const data = '0x' + sel(sig) + (args || '');
      try { const r = await h.call(addr, data, value !== undefined ? { value: BigInt(value) } : {}); out.push({ sig, success: r.success, returnHex: r.returnHex }); }
      catch (e) { out.push({ sig, success: false, returnHex: 'THROW:' + String(e?.message ?? e).slice(0, 80) }); }
    }
    return out;
  };
  if (!cj.ok) {
    if (!cs.ok) return { label, class: 'BOTH-REJECT', codes: cj.codes, solcErr: cs.err };
    let h, as, solcRuns;
    try { h = await Harness.create(); as = await h.deploy(cs.creation); solcRuns = await runAll(as, h); }
    catch (e) { return { label, class: 'JETH-REJECT', codes: cj.codes, note: String(e?.message ?? e).slice(0, 120) }; }
    return { label, class: solcRuns.some((r) => r.success) ? 'OVER-REJECTION' : 'BOTH-REJECT', codes: cj.codes, solcRuns };
  }
  if (!cs.ok) return { label, class: 'OVER-ACCEPTANCE', solcErr: cs.err };
  let h, aj, as;
  try { h = await Harness.create(); aj = await h.deploy(cj.bytecode); as = await h.deploy(cs.creation); }
  catch (e) { return { label, class: 'DEPLOY-ERR', detail: String(e?.message ?? e).slice(0, 200) }; }
  const rj = await runAll(aj, h), rs = await runAll(as, h);
  const diffs = [];
  for (let i = 0; i < callsArr.length; i++) {
    const a = rj[i], b = rs[i];
    if (a.success === b.success && a.returnHex === b.returnHex) continue;
    const cls = a.success && b.success ? 'MISCOMPILE(both-ok,diff-bytes)' : a.success && !b.success ? 'DIVERGE(jeth-ok,solc-revert)' : !a.success && b.success ? 'DIVERGE(jeth-revert,solc-ok)' : 'DIVERGE(both-revert,diff)';
    diffs.push({ sig: a.sig, args: callsArr[i][1] || '', cls, jeth: a, solc: b });
  }
  return diffs.length ? { label, class: 'DIVERGE', diffs } : { label, class: 'MATCH' };
}
```
