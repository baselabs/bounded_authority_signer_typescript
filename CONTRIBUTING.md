---
title: "Contributing"
category: Package policies
---

# Contributing

Use Node, Deno, Python, Bun and uv at the exact versions in `.tool-versions` and the pnpm version
in `package.json`. Activate that pnpm with Corepack, then run `pnpm install --frozen-lockfile`.
No credential or service is required for documentation checks; npm registry access is required.

Run `pnpm build`, `pnpm typecheck`, `pnpm typecheck:browser`, `pnpm typecheck:web`, `pnpm lint`,
`pnpm guard:browser`, `pnpm size`, `pnpm test`, `pnpm test:portable`, `pnpm test:network`,
`pnpm test:tarball`, `pnpm test:runtimes`, `pnpm docs:api` and `pnpm check:currency` for qualification.
`pnpm test:tarball` executes every Node documentation journey against both the packed candidate and
exact registry release. `BAP_SAMPLE_MODE=candidate` or `published` selects just one mode explicitly.
Install the Playwright browsers with `pnpm exec playwright install --with-deps`, build the site with
`pnpm build:site`, then run `pnpm test:browser` and `pnpm test:playground` with
`BAP_BROWSERS=chromium,firefox,webkit`. DOM samples execute in those engines, never in Node.

For notebooks, run `uv sync --frozen`, then `pnpm notebooks:local` and `pnpm notebooks:published`.
The runner installs an isolated Deno Jupyter kernel and removes its workspace and caches afterward.
It executes notebook cells in the real kernel, not a concatenated script. Every code cell has
persisted semantic stdout; compare fixed meanings, never generated keys or signatures.

Author guides under `docs/guides/`, notebooks under `docs/notebooks/`, and register notebooks in
`docs/notebooks/registry.json`. TypeScript examples carry a `readme-sample` marker and a matching
`readme-output` text fence. CommonMark discovery includes nested fences, TSDoc and HTML samples.
Use `run` for Node and `run-dom` for browser code; helpers use `file NAME.ts`, declarations `types`.
Shell setup uses `setup`. An executable example without asserted output fails qualification.

Keep the README under 32 KiB. The currency tests enforce links, anchors, error completeness,
version pins and API member docs. Update CHANGELOG for behavior, dependency or contract changes.
Use real cryptography and real services; never replace services with mocks. Public text contains
no customer identities, secrets or private deployment details.

Commit named files. Maintainers qualify a commit through a push to `kci/<sha>`; the last job
`qualified` must pass before `main` moves to that exact commit. Contributors do not dispatch
workflows, push release tags, publish packages or deploy Pages. Releases and Pages are separate,
owner-dispatched workflows. Report security issues through [SECURITY.md](SECURITY.md).

Apache-2.0 contributions must keep the public-key-only protocol boundary intact.
