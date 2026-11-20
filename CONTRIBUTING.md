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
`pnpm site` runs the web typecheck, playground build, browser bundle scan, released API build,
released API checks and npm version checks, in that order. The separate `site` qualification
job runs it from a frozen install before any library build; Pages runs the same command.
The released API uses the tag's own TypeDoc, plugins and types from its frozen install,
and fails closed if that install has no TypeDoc.
`pnpm test:tarball` executes every Node documentation journey against the packed candidate.
`pnpm test:playground` also uses the candidate; the published variants run only after upload.
Install the Playwright browsers with `pnpm exec playwright install --with-deps`, build the site with
`pnpm build:site`, then run `pnpm test:browser` and `pnpm test:playground` with
`BAP_BROWSERS=chromium,firefox,webkit`. DOM samples execute in those engines, never in Node.

For notebooks, install the exact Node, Deno, Python and uv versions in `.tool-versions` and
activate the declared pnpm. The second Node version on the `nodejs` line is the extra
compatibility lane; notebook checks use the first. Run `pnpm install --frozen-lockfile`,
`uv lock --check` and `uv sync --frozen`, then `pnpm notebooks:local`.

Both notebook scripts call `scripts/check_notebooks.py`. Register every notebook in
`docs/notebooks/registry.json`: schema 1 records the package identity, exact npm package pins,
and an ordered `notebooks` list of `file` and `title` entries. The file list must match the
notebook directory in both directions.

`--local` installs the candidate tarball from `tools/pack.mjs`, the same packer the package gate
inspects. `--published` installs exact releases from `https://registry.npmjs.org/` and checks
registry identity, tarball URL and SHA-512 integrity. Both compare installed files with the archive
bytes and check in the real kernel that `npm:` imports resolve to that inspected installation.
Notebook cells are unchanged in both modes.

The runner uses nbclient and a fresh real Deno Jupyter kernel for each notebook. It never
concatenates cells. Saved Jupyter outputs are the sole expected outputs; it normalizes stdout
chunks, line endings, ANSI color and display counts before comparing semantic text. Assertions
stay in each cell. Never persist keys, signatures, nonce values or wall-clock times.

Missing files, unregistered notebooks, empty code, missing output, kernel errors, output
mismatches, changed files and filesystem residue fail the run. The runner shuts down kernels
and removes its scratch consumers, inspected tarballs, temporary kernel registration and caches,
including on failure. Generated development API documentation is a qualification check; publication
uses the immutable release documentation.

Candidate notebook and consumer journeys install this repository's package from the packed candidate.
`publish.yml` waits up to ten minutes in the upload job for npm to serve the exact inspected
archive. Pending owner approval fails that run clearly; dispatch the same commit after approval.
The keyless `published-notebooks` job runs only after byte-for-byte registry read-back succeeds.
A maintainer can run `pnpm notebooks:published` and `pnpm docs:checks:published` on demand
once that version is available. Infra tags the release; `pages.yml` then runs `pnpm site`,
which builds `/api/` from that tag and checks it with `pnpm test:network:pages`.
Qualification checks the current npm release through the same pipeline; no publication job waits on a tag.
The upload job and its environment gate are separate.

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
