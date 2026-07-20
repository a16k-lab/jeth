## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).

## a16k-lab brand lockup

- Always render the a16k-lab attribution as one compact horizontal lockup: a 28 px circular logo, a 9 px gap, and the text `Built by @a16k-lab` with only `@a16k-lab` emphasized.
- Do not place the lockup in a pill, card, bordered container, background, or shadow.
- Keep the logo and attribution text together. Never render either one alone.
- In the HTML documentation, reuse `organizationLockup()` from `scripts/build-docs.mts` instead of recreating the markup or styling.

## JETH product logo

- The canonical JETH product logos live in `assets/jeth/`.
- Use the orange JETH icon as the default product mark, especially in documentation, favicons, social previews, package listings, and editor integrations.
- Use the monochrome logo only when a neutral, print-oriented treatment is explicitly required.
- Do not recreate the JETH mark with text, CSS shapes, emoji, unrelated Ethereum artwork, or substitute logos.
- Choose the smallest supplied raster size that remains sharp at the intended rendered size. Do not upscale a smaller source.
