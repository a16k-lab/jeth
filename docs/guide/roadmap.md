# Product roadmap

Built by [@a16k-lab](https://github.com/a16k-lab).

This roadmap turns JETH from a strong compiler research project into a product
that can be installed, integrated, reviewed, and operated safely. The order is
intentional: release trust comes before adding a large new language surface.

## Release principles

1. No known miscompiles at release.
2. Accepted behavior has executable evidence.
3. Unsupported behavior rejects cleanly.
4. Builds are reproducible and attributable to an exact toolchain.
5. Documentation and artifacts are versioned with the compiler.
6. Security claims are scoped and independently reviewable.

## R0: release foundation

Goal: make the existing compiler installable, deterministic, and supportable.

- Resolve package name, ownership, public/private status, and the GPLv3 versus
  MIT metadata mismatch.
- Add a `bin` entry and publish `jethc` as a versioned package, then provide
  checksummed standalone binaries.
- Define semver, compiler/language versioning, changelog, compatibility window,
  and deprecation policy.
- Add CI across supported operating systems and Node versions.
- Generate reproducible artifacts, checksums, SBOM, and signed provenance.
- Add `SECURITY.md`, a private reporting channel, and an incident process.
- Freeze the first artifact schema and EVM-target policy.

Exit criteria: a clean checkout can install a pinned release, compile an example,
reproduce published artifacts, and report a security issue without relying on a
developer workstation.

## R1: professional CLI and developer experience

Goal: make JETH pleasant and dependable in real projects.

- Project config, multi-file builds, contract selection, imports, and output
  profiles.
- Structured diagnostics, snippets, stable exit codes, warnings policy, and
  standard JSON mode.
- A deterministic local EVM runner for deploy/call scenarios, fixture state,
  snapshots, traces, revert decoding, and reproducible fork configuration.
- Source maps, source-level traces, revert decoding, gas reports, and storage
  layout diffs.
- Incremental/watch builds and a validated content-addressed cache.
- LSP, editor extensions, formatter integration, and generated docs on hover.
- Foundry/Hardhat adapters, deployment/linking helpers, and explorer verification.

Exit criteria: a small team can develop, test, deploy, verify, and debug a JETH
project without calling internal compiler APIs.

## R2: compiler correctness and conformance

Goal: make the safety bar durable as the compiler evolves.

- Convert the supported matrix into machine-readable capabilities and generated
  conformance cases.
- Expand grammar, type, location, aliasing, inheritance, call, ABI, storage,
  proxy, and optimizer fuzzing.
- Preserve deploy/run/decode comparisons with solc 0.8.35, then define a process
  for adding future solc baselines.
- Add metamorphic tests, invariant tests, test-order shuffling, deterministic
  seeds, timeouts, and corpus minimization.
- Audit optimizer transformations with semantic equivalence and gas baselines.
- Prioritize OR lifts by user impact, workaround quality, implementation risk,
  and proof coverage. Do not optimize for the raw number of accepted constructs.

Exit criteria: each acceptance decision can be traced to a capability, tests,
and an explicit compiler invariant.

## R3: language and runtime completeness

Goal: close the remaining practical gaps without weakening soundness.

- Work through the current "Still gated" list in `SUPPORTED.md`.
- Prioritize common contract and ABI shapes, arbitrary contract construction
  beyond the existing EIP-1167 CREATE/CREATE2 clone surface, function values
  where safely expressible, and storage-reference library workflows.
- Improve import/package boundaries and deterministic dependency resolution.
- Add analyzer checks that prevent proxy/storage misuse and common application
  hazards where the compiler has enough information to prove them.
- Add opt-in optimizer passes only with before/after semantic and gas evidence.

Exit criteria: representative token, vault, governance, oracle, library, proxy,
and diamond projects compile without unsafe workarounds.

## R4: offline AI verification lab

Goal: use local models to increase adversarial coverage without trusting model
judgment as a security boundary.

### Architecture

1. A local LLM, SLM, or reasoning model proposes tests, mutations, invariants,
   or audit hypotheses.
2. A grammar-aware generator keeps candidates inside a chosen language region.
3. JETH and solc compile equivalent programs.
4. A local EVM deploys and executes both with generated calls and state.
5. An oracle compares bytes, logs, slots, gas classes, and diagnostics.
6. A reducer produces a minimal permanent regression.

### Model strategy

- Begin with retrieval, constrained generation, and tool feedback around a strong
  local base model.
- Build a normalized corpus of fixes, rejects, parity mirrors, diagnostics, and
  minimized failures.
- Fine-tune only after evaluation is stable and leakage-resistant.
- Maintain held-out bug families and score reproduction rate, unique findings,
  false-positive burden, reduction quality, and compute cost.
- Let models propose. Let deterministic execution and compiler invariants decide.

Exit criteria: the lab repeatedly finds novel, reproducible issues on held-out
campaigns and adds minimized tests without creating flaky or unverifiable claims.

## R5: audited numerical packages

Goal: provide useful on-chain math with explicit semantics and bounded risk.

### First package

- full-precision multiplication/division;
- signed and unsigned fixed-point types;
- explicit floor, ceil, toward-zero, and nearest rounding;
- saturating and checked variants where the distinction is visible in the name;
- units and range-constrained branded types;
- roots, powers, logarithms, and exponentials with documented error bounds;
- vector and statistics helpers only after gas and overflow analysis.

### Calculus-like functionality

Integrals, derivatives, and differential methods should not emulate real numbers
implicitly. Choose one of two explicit models:

- compile-time symbolic transformation for supported expressions; or
- runtime numerical approximation with fixed-point input, a stated algorithm,
  domain restrictions, convergence conditions, maximum error, iteration cap,
  rounding mode, and worst-case gas.

Keep numerical packages outside the compiler core, version them separately, and
commission specialized audits. The compiler may later add verified intrinsics for
proven hot paths without changing package-level semantics.

Exit criteria: every function has a precise numeric contract, reference vectors,
differential tests, gas bounds, and independent review.

## R6: production trust and ecosystem

Goal: make JETH credible for high-value deployment.

- Independent compiler, CLI, standard-library, and generated-proxy audits.
- Public bug bounty and transparent advisories.
- Long-running fuzzing infrastructure with retained corpora and seeds.
- Reproducible release ceremony and signed release index.
- Stable documentation website with version switching and searchable diagnostics.
- Reference projects, migration guides, training material, and maintainer policy.
- Governance for language proposals and backwards compatibility.

Exit criteria: production users can evaluate exactly what was audited, reproduce
their compiler, understand compatibility, and receive fixes through a documented
security lifecycle.

## What not to do

- Do not market the compiler or a math package as fully safe because tests pass.
- Do not let an LLM approve code, diagnostics, or security findings without an
  executable oracle and human review.
- Do not lift an OR solely to increase feature count.
- Do not publish a package while license, artifact, or version metadata conflict.
- Do not make optimizer changes without semantic regression and gas evidence.
