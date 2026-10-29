"""Smoke test: import every third-party module the app imports.

Run inside the built image (python -). Catches dependency bumps that remove or
rename a package, or leave one uninstallable. It does not start the service.
"""
import ast
import importlib
import pathlib
import subprocess
import sys

APP = pathlib.Path("/app")
sys.path[:0] = [str(APP), str(APP / "proto")]

local = {p.stem for p in APP.glob("*.py")} | {p.name for p in APP.iterdir() if p.is_dir()}
wanted = set()
for path in APP.rglob("*.py"):
    if "test" in path.name or "node_modules" in path.parts:
        continue
    for node in ast.walk(ast.parse(path.read_text(), str(path))):
        if isinstance(node, ast.Import):
            wanted.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            wanted.add(node.module)

failed = []
for name in sorted(wanted):
    top = name.split(".")[0]
    if top in sys.stdlib_module_names or top in local or top.endswith("_pb2"):
        continue
    try:
        importlib.import_module(name)
        print(f"ok   {name}")
    except Exception as exc:  # any failure to import is a smoke failure
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
        failed.append(name)

print("--- pip check (informational) ---")
subprocess.run([sys.executable, "-m", "pip", "check"])

if failed:
    sys.exit(f"{len(failed)} import(s) failed: {', '.join(failed)}")
print(f"all {len(wanted)} imports resolved")
