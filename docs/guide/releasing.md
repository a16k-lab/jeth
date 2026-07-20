# Versioning and releases

JETH uses [Changesets](https://github.com/changesets/changesets) to collect
release notes, calculate Semantic Versioning updates, and maintain
[`CHANGELOG.md`](../../CHANGELOG.md). The current baseline is `0.1.0`.

> [!IMPORTANT] JETH is still a private package. Changesets can update its version
> and changelog, but npm publication and release tags remain disabled until the
> package metadata, CLI entry point, license, and release artifacts are ready.

## Version policy before 1.0

| Changeset type | Version example | Use it for |
| --- | --- | --- |
| `patch` | `0.1.0` to `0.1.1` | Correctness fixes, safe analyzer checks, optimizations without observable incompatibility, documentation, and compatible tooling fixes |
| `minor` | `0.1.0` to `0.2.0` | New language or CLI features and intentional breaking changes while JETH remains pre-1.0 |
| `major` | `0.1.0` to `1.0.0` | The explicit 1.0 stability commitment, then incompatible changes after 1.0 |

A compiler miscompile fix is normally a patch release when it only makes an
invalidly accepted program reject or corrects behavior to match the documented
language. If a correction intentionally changes documented, supported behavior,
call it out as a breaking pre-1.0 change and use a minor release.

## Add a changeset

Every user-visible compiler, runner, analyzer, CLI, or documentation change that
belongs in release notes should include a changeset.

```bash
npm run changeset
```

Choose the `jeth` package, select `patch`, `minor`, or `major`, and write a short
summary in user-facing language. The command creates a Markdown file under
`.changeset/`. Commit that file with the implementation.

Changes that do not affect a release, such as internal test refactors, may omit
a changeset.

## Inspect the pending release

```bash
npm run changeset:status
```

Review the proposed version and every summary. For compiler work, complete the
normal differential, full-suite, and shuffled-file gates before applying the
release plan.

## Apply a release version

Run the version command only from a clean release branch after all intended
changesets have landed:

```bash
npm run version-packages
```

This consumes the pending changeset files, updates `package.json`, and adds the
entries to `CHANGELOG.md`. Review those changes before committing them. The
current configuration never creates commits automatically.

## Publish later

Do not run `changeset publish` yet. Before enabling npm publication:

1. Resolve the repository license metadata mismatch.
2. Add the public package files, `bin` entry, and tested installation path.
3. Remove `private: true` deliberately.
4. Set the intended npm access and provenance policy.
5. Add release CI, signed tags, checksums, SBOM, and artifact verification.
6. Test installation and compiler execution from the packed tarball.

Until those gates are complete, Changesets is the source of truth for versions
and changelog entries, not a publication mechanism.
