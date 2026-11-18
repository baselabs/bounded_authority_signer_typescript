---
title: "Executable notebooks"
category: Notebooks
---

# Executable notebooks

Install the exact tools in `.tool-versions`, run `uv sync --frozen`, then `uv run --frozen deno jupyter --install`.
Open any notebook below in JupyterLab or VS Code, select the Deno kernel and Run All from a fresh
kernel. Native TypeScript cells import the exact published npm packages. No hidden key or service
setup is required. Never save private values in cell outputs.

For automated checks use `pnpm notebooks:local` (packed candidate) or
`pnpm notebooks:published` (unchanged notebooks, exact registry release). Both execute with
Jupyter's nbclient in the real Deno kernel. The runner compares every persisted semantic output,
asserts package version and installation origin, shuts down the kernel and removes its caches and
workspace. A failed cell or missing output is a failure, not a skipped demonstration.

- [Grant and proof](grant-and-proof.ipynb)
- [Bounded selectors and ES256](bounded-selectors-es256.ipynb)
- [Key custody](key-custody.ipynb)
- [Local loopback](local-loopback.ipynb)
- [Anchors and transitions](anchors-and-transitions.ipynb)

These notebook sources are also linked from the generated API site. Download the ipynb files to run them; the registry view renders their saved outputs.
