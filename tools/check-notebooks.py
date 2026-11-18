"""Execute registered ipynb files cell-by-cell in a fresh, real Deno Jupyter kernel."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(*args: str, cwd: Path, env: dict[str, str]) -> str:
    return subprocess.run(args, cwd=cwd, env=env, check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300).stdout.strip()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def stdout(cell: dict) -> str:
    require(not any(item.get("output_type") == "error" for item in cell.get("outputs", [])), "cell error")
    return "".join("".join(item["text"]) for item in cell.get("outputs", [])
                   if item.get("output_type") == "stream" and item.get("name") == "stdout").rstrip()


def main() -> None:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--local", action="store_true")
    modes.add_argument("--published", action="store_true")
    args = parser.parse_args()
    pins = {parts[0]: parts[1] for line in (ROOT / ".tool-versions").read_text().splitlines() if (parts := line.split())}
    require(sys.version.split()[0] == pins["python"], "Python differs from .tool-versions")
    env = dict(os.environ)
    require(run("deno", "--version", cwd=ROOT, env=env).splitlines()[0] == f'deno {pins["deno"]}', "Deno version differs")
    manifest = json.loads((ROOT / "package.json").read_text())
    name, version = manifest["name"], manifest["version"]
    verifier_name = "@bounded-authority-protocol/verifier"
    verifier_version = re.sub(r"^[~^]", "", manifest["dependencies"][verifier_name])
    directory = ROOT / "docs/notebooks"
    registry = json.loads((directory / "registry.json").read_text())["notebooks"]
    names = [entry["file"] for entry in registry]
    require(len(names) == len(set(names)) and sorted(names) == sorted(path.name for path in directory.glob("*.ipynb")), "notebook registry mismatch")
    require(bool(names), "empty notebook registry")
    for file in names:
        original = json.loads((directory / file).read_text())
        require(original["metadata"]["kernelspec"]["name"] == "deno", f"{file}: not the Deno kernel")
        code = [cell for cell in original["cells"] if cell["cell_type"] == "code"]
        require(bool(code), f"{file}: no code cells")
        for cell in code:
            require(bool(cell.get("outputs")) and bool(stdout(cell)), f"{file}: missing persisted semantic stdout")
        source = "\n".join("".join(cell["source"]) for cell in code)
        require(f"npm:{name}@{version}" in source, f"{file}: missing exact signer dependency")
        for package, pin in re.findall(r"npm:(@bounded-authority-protocol/(?:signer|verifier))@([^\"'\s/]+)", source):
            require(pin == (version if package == name else verifier_version), f"{file}: stale {package} pin {pin}")
        temporary = tempfile.TemporaryDirectory(prefix="bap-notebook-")
        scratch = Path(temporary.name)
        try:
            # All runner-owned state, including kernel registration and resolver caches, is scoped here.
            for key, sub in [("DENO_DIR", "deno"), ("JUPYTER_DATA_DIR", "jupyter"),
                             ("JUPYTER_RUNTIME_DIR", "runtime"), ("JUPYTER_CONFIG_DIR", "config"),
                             ("npm_config_cache", "npm-cache")]:
                env[key] = str(scratch / sub)
            env["NO_COLOR"] = "1"
            consumer = scratch / "consumer"
            consumer.mkdir()
            (consumer / "package.json").write_text('{"type":"module","private":true}')
            (consumer / "deno.json").write_text(json.dumps({"nodeModulesDir": "manual", "lock": False}))
            artifact = None
            if args.local:
                # Same packer used by the package gate and release inspection, never a source shim.
                artifact = json.loads(run("node", str(ROOT / "tools/pack.mjs"), "--out", str(scratch / "packed"), cwd=ROOT, env=env))["file"]
            metadata = json.loads(run("npm", "view", f"{name}@{version}", "--json", "--registry=https://registry.npmjs.org", cwd=consumer, env=env))
            require(metadata["name"] == name and metadata["version"] == version, "registry identity mismatch")
            require(metadata["dist"]["tarball"].startswith("https://registry.npmjs.org/"), "noncanonical registry origin")
            run("npm", "install", "--ignore-scripts", "--registry=https://registry.npmjs.org",
                artifact or f"{name}@{version}", f"{verifier_name}@{verifier_version}", cwd=consumer, env=env)
            installed = json.loads((consumer / "node_modules" / name / "package.json").read_text())
            require(installed["name"] == name and installed["version"] == version, "installed identity mismatch")
            lock = json.loads((consumer / "package-lock.json").read_text())
            verifier_metadata = json.loads(run("npm", "view", f"{verifier_name}@{verifier_version}", "--json", "--registry=https://registry.npmjs.org", cwd=consumer, env=env))
            verifier_entry = lock["packages"]["node_modules/" + verifier_name]
            require(verifier_metadata["name"] == verifier_name and verifier_metadata["version"] == verifier_version, "verifier registry identity mismatch")
            require(verifier_metadata["dist"]["tarball"].startswith("https://registry.npmjs.org/"), "verifier registry origin mismatch")
            require(verifier_entry["version"] == verifier_version and verifier_entry["resolved"] == verifier_metadata["dist"]["tarball"] and verifier_entry["integrity"] == verifier_metadata["dist"]["integrity"], "verifier installation origin mismatch")
            entry = lock["packages"]["node_modules/" + name]
            if args.published:
                require(entry["resolved"] == metadata["dist"]["tarball"] and entry["integrity"] == metadata["dist"]["integrity"], "registry origin or integrity mismatch")
            else:
                import base64
                digest = "sha512-" + base64.b64encode(hashlib.sha512(Path(artifact).read_bytes()).digest()).decode()
                require(entry["resolved"].startswith("file:") and entry["integrity"] == digest, "candidate archive mismatch")
            run("deno", "jupyter", "--install", cwd=consumer, env=env)
            # Imports occur after selecting isolated Jupyter directories; the kernel manager sees them.
            os.environ.update({key: value for key, value in env.items() if key.startswith("JUPYTER_")})
            import nbformat
            from nbclient import NotebookClient
            nb = nbformat.from_dict(copy.deepcopy(original))
            if args.local:
                for cell in nb.cells:
                    if cell.cell_type == "code":
                        cell.source = cell.source.replace(f"npm:{name}@{version}/package.json", (consumer / "node_modules" / name / "package.json").as_uri())
                        cell.source = cell.source.replace(f"npm:{name}@{version}", (consumer / "node_modules" / name / "dist/src/index.js").as_uri())
            # Bind the npm module's executed exports to the inspected installation. Namespace
            # identity avoids assuming that import.meta.resolve expands npm: URLs into file: URLs.
            signer_file = (consumer / "node_modules" / name / installed["main"]).as_uri()
            verifier_installed = json.loads((consumer / "node_modules" / verifier_name / "package.json").read_text())
            verifier_file = (consumer / "node_modules" / verifier_name / verifier_installed["main"]).as_uri()
            specifier = signer_file if args.local else f"npm:{name}@{version}"
            probe = nbformat.v4.new_code_cell(
                f'const signerFromImport = await import({json.dumps(specifier)});\n'
                f'const signerFromArchive = await import({json.dumps(signer_file)});\n'
                'if (signerFromImport.signGrant !== signerFromArchive.signGrant) throw new Error("unexpected signer origin");\n'
                f'const verifierFromImport = await import({json.dumps(f"npm:{verifier_name}@{verifier_version}")});\n'
                f'const verifierFromArchive = await import({json.dumps(verifier_file)});\n'
                'if (verifierFromImport.checkEnvelope !== verifierFromArchive.checkEnvelope) throw new Error("unexpected verifier origin");\n'
                'console.log("installed signer origin checked");')
            nb.cells.insert(0, probe)
            baseline = sorted(path.relative_to(consumer).as_posix() for path in consumer.rglob("*") if "node_modules" not in path.parts)
            client = NotebookClient(nb, kernel_name="deno", timeout=180, allow_errors=False,
                                    resources={"metadata": {"path": str(consumer)}})
            client.execute(env=env)
            require(stdout(nb.cells[0]) == "installed signer origin checked", "kernel origin probe failed")
            executed = [cell for cell in nb.cells[1:] if cell.cell_type == "code"]
            require(len(code) == len(executed), f"{file}: skipped code cell")
            for i, (expected, actual) in enumerate(zip(code, executed), 1):
                require(actual.execution_count is not None, f"{file}: cell {i} not executed")
                require(stdout(actual) == stdout(expected), f"{file}: cell {i} output mismatch: {stdout(actual)!r} != {stdout(expected)!r}")
            residue = sorted(path.relative_to(consumer).as_posix() for path in consumer.rglob("*") if "node_modules" not in path.parts)
            require(residue == baseline, f"{file}: notebook left residue")
            print(f"PASS {file}: {len(executed)} cells ({'local' if args.local else 'published'})")
        finally:
            temporary.cleanup()
            require(not scratch.exists(), f"runner residue: {scratch}")


if __name__ == "__main__":
    main()
