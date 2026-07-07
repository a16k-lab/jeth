# NEXT STEPS (quick reference)

Full detail + harness source: [`docs/HANDOFF-pointer-headed-coverage.md`](./HANDOFF-pointer-headed-coverage.md).

## Where you are

- `main` @ `18d6ae6` (+ handoff docs on top), suite **393 files / 3599 tests** green, `tsc` clean.
- The pointer-headed `Arr<In,N>` (fixed array of a *static* struct) consumer surface is enumerated and proven
  complete-by-construction; **8 consumers fixed**; **1 remains** (the 9th), then loop to clean.
- ABSOLUTE BAR: **zero miscompiles, zero over-acceptances** (a clean reject / Panic beats wrong bytes). Judge
  ONLY via the differential harness (behavioral byte-identity vs solc 0.8.35 **legacy** pipeline).
- **Do NOT flatten `Arr<In,N>`** - solc's `In[N] memory` is itself pointer-headed with reference aliasing; a
  flat layout would miscompile it. Fix each bad consumer to be pointer-aware, byte-identical.

## Step 1 - fix the 9th consumer (a real miscompile on `18d6ae6`)

- **Shape:** a multi-value tuple return whose component is a fixed-array ELEMENT `m[i]` of type `Arr<In,N>`
  (source `Arr<Arr<In,N>,M>` or `Arr<In,N>[]`).
- **Repro:** `return [42n, m[1n]]` -> solc `[42,15,16,17,18]`; JETH `[42, 0xa0, 0,0,0, 15,16,17,18]` (a bogus
  dynamic offset for an ABI-static array). Full repro in the handoff doc.
- **Root cause:** `src/yul.ts` multi-return tuple encoder, the `arrayValue` / `memArray`-base branch, missing
  the `isDynamicType(t)` / `t.length===undefined` guard, so it offset-encodes a static fixed array as dynamic.
- **Fix (mirror commit `e33d131` - `git show e33d131` first):** inline the static fixed array via
  `abiEncFromMem` instead of offset-encoding it. Keep MATCHing: `abi.encode(m[i])` single-arg, and
  `return [42, plainLocalArr]` (the `e33d131` branch).

## Step 2 - loop the coverage proof to convergence

Re-run enumerate -> exhaustively differential-test -> prove. Fix each finding (byte-identical pointer-aware
consumer, OR a clean reject matching solc-legacy). Commit + full suite + push each. Repeat until
**FULLY-COVERED-CLEAN** (0 violations, no uncovered sites). Cover the CONSUMER axis (that is where leaks hide):
every source {literal, `new Array<In>(n)`, calldata param, storage, memory local, internal-call result,
external-call result, `abi.decode`, struct field} x every consumer {return, `abi.encode*`, event, revert/error,
internal/external call arg, tuple return incl element source, struct-field, storage assign/push, mapping,
getter, ternary, for-of, delete, element/field read+write, `.length`, nested `Arr<Arr<In,N>,M>`}.

## Execution recipe

1. `export PATH="$HOME/.nvm/versions/node/v22.22.2/bin:$PATH"`; run via `npx tsx` / `npx vitest`.
2. Differential harness = the `diff.mjs` in the handoff doc Appendix (recreate; fix the 4 import paths). `diff()`
   returns a `class` in `MATCH|BOTH-REJECT|OVER-REJECTION|OVER-ACCEPTANCE|DIVERGE`. solc contract named `C`.
   RUN + DECODE with DISTINCT non-zero values (a zero / raw-pointer tail must not masquerade as a match).
3. `graphify query "<q>"` before reading source; `graphify update .` after editing.
4. Fix -> `npx tsc --noEmit` clean -> add a non-vacuous run+decode test -> `npx vitest run
   --hookTimeout=120000 --testTimeout=120000` -> **gate `git push` on a green suite in a SEPARATE step**.
5. Prefer worktree-isolated fix + independent adversarial-verify (the verifier repeatedly catches mistakes);
   cherry-pick clean onto `main`; full suite; push.

## Traps

- "both compile" != byte-identical -> run + decode.
- Expanded-tuple-selector vacuity: a struct/array-of-struct param dispatches on `f((uint256,(uint256,uint256)[2]))`,
  not `f(S)`; build values inside the function + anchor a decoded scalar.
- solc legacy `UnimplementedFeatureError` (e.g. mem/cd struct-array -> storage) = the reference's hard wall (no
  viaIR) -> JETH must REJECT (`JETH470`), never accept-and-guess. Next free diag code: `JETH471`.
- Every JETH int literal needs the `n` suffix.
- Documented deviation (do NOT "fix"): `@pure` may call `this.internalMethod()` - see `docs/distinctive-features.md`.
