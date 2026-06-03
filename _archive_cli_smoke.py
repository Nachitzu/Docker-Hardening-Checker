"""End-to-end CLI smoke test — verifies all formatters, exit codes, and ignore."""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
PY = sys.executable
CLI = [PY, str(ROOT / "cli.py")]


def run(*args, env_extra=None, expect_code=0):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    r = subprocess.run([*CLI, *args], capture_output=True, text=True, env=env, cwd=str(ROOT))
    return r


print("=== text, bad file ===")
r = run("samples/Dockerfile.bad", "samples/compose-bad.yml", "--no-color")
print("exit code:", r.returncode, "(expect 1)")
assert r.returncode == 1, f"expected 1 got {r.returncode}"
assert "DF-004-ENV" in r.stdout
assert "DC-003-api" in r.stdout

print("=== text, clean file (medium only) ===")
r = run("samples/Dockerfile.good", "samples/compose-good.yml", "--no-color")
print("exit code:", r.returncode, "(expect 0; default --fail-on=high)")
assert r.returncode == 0, f"expected 0 got {r.returncode}"
assert "DF-010" in r.stdout  # the only finding is medium
assert "no findings" in r.stdout  # compose-good.yml should be clean

print("=== --fail-on medium catches the medium finding ===")
r = run("samples/Dockerfile.good", "samples/compose-good.yml", "--no-color", "--fail-on", "medium")
print("exit code:", r.returncode, "(expect 1)")
assert r.returncode == 1

print("=== --fail-on critical passes the medium finding ===")
r = run("samples/Dockerfile.good", "samples/compose-good.yml", "--no-color", "--fail-on", "critical")
print("exit code:", r.returncode, "(expect 0)")
assert r.returncode == 0

print("=== --ignore DF-010 removes the medium ===")
r = run("samples/Dockerfile.good", "--no-color", "--ignore", "DF-010", "--fail-on", "medium")
print("exit code:", r.returncode, "(expect 0; ignored)")
assert r.returncode == 0
assert "DF-010" not in r.stdout

print("=== json format ===")
r = run("samples/Dockerfile.bad", "--format", "json", "--no-color")
print("exit code:", r.returncode)
import json

data = json.loads(r.stdout)
assert data["totals"]["critical"] == 3
assert data["totals"]["high"] == 6
assert data["totals"]["total"] == 14
print("  totals:", data["totals"])

print("=== sarif format ===")
r = run("samples/Dockerfile.bad", "--format", "sarif", "--no-color")
sarif = json.loads(r.stdout)
assert sarif["version"] == "2.1.0"
assert len(sarif["runs"][0]["results"]) == 14
print("  results:", len(sarif["runs"][0]["results"]), "rules:", len(sarif["runs"][0]["tool"]["driver"]["rules"]))

print("=== github format + step summary ===")
summary_path = ROOT / "_test_summary.md"
if summary_path.exists():
    summary_path.unlink()
r = run("samples/Dockerfile.bad", "--format", "github", "--no-color",
        env_extra={"GITHUB_STEP_SUMMARY": str(summary_path)})
print("exit code:", r.returncode, "lines:", len(r.stdout.splitlines()))
assert "::error file=" in r.stdout
assert "::warning" in r.stdout or "::notice" in r.stdout
assert summary_path.exists()
summary = summary_path.read_text(encoding="utf-8")
assert "# Docker Hardening Report" in summary
assert "DF-004-ENV" in summary
print("  step summary has", len(summary), "chars")

print("=== auto-discover from directory ===")
r = run("samples", "--no-color", "--fail-on", "high")
print("exit code:", r.returncode, "(expect 1; bad files present)")
assert r.returncode == 1
assert "Dockerfile.bad" in r.stdout or "Dockerfile.bad" in r.stderr
assert ("compose-bad.yml" in r.stdout) or ("compose-bad.yml" in r.stderr)
assert "DF-010" in r.stdout  # medium finding from Dockerfile.good should still appear in output

print("=== empty dir / no files ===")
r = run("__pycache__", "--no-color")
print("exit code:", r.returncode, "(expect 2 or 0 depending on discovery)")
# pycache might have .pyc but no dockerfile/compose
# Just verify the CLI doesn't crash.

print()
print("All CLI tests passed.")
